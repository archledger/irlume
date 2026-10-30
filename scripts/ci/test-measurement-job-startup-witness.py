#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Bounded startup evidence codec; no service, runtime or VM is executed."""

import copy
import hashlib
import importlib.util
import json
import os
import unittest
from pathlib import Path
from types import MappingProxyType
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


codec = load("witness", "measurement-job-startup-witness.py")
preflight_tests = load("witness_preflight_tests", "test-measurement-job-preflight.py")
state_tests = load("witness_state_tests", "test-measurement-job-runtime-state.py")


class WitnessTests(unittest.TestCase):
    def setUp(self):
        fixture = preflight_tests.AdapterTests(
            "test_raw_snapshot_schema_matches_collector_shape"
        )
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.plan = fixture.plan
        self.deps = codec.Dependencies(preflight_tests.preflight, state_tests.state)
        _, self.manifest = preflight_tests.fixtures.fixtures.selection()
        initial = fixture.raw
        # The runtime lives on G's root mount, as stat and maps both report.
        mounts = preflight_tests.preflight.root.parse_mountinfo(
            initial["proc"]["mountinfo"]
        )
        self.device = mounts["/"].device
        _, files, python, maps = state_tests.observation(self.device)
        old = "/opt/irlume/entry.py"
        new = "/opt/irlume/measurement-job-guardian-native.py"
        files[new] = files.pop(old)
        python["modules"][0]["origin"] = new
        initial["proc"]["maps"] = maps
        # G's own digests of its runtime's pages, never decoded from a witness.
        self.pages = state_tests.page_digests(files)
        final = copy.deepcopy(initial)
        final["finished_ns"] = 450
        core = self.deps.preflight.core_witness(self.plan, final, 1000, 500)
        self.observation = {
            "initial_filesystem": initial,
            "filesystem": final,
            "core": core,
            "runtime_manifest_sha256": self.plan["manifest"]["sha256"],
            "files": files,
            "python": python,
            "maps": maps,
            "mapped": state_tests.mapped_rows(maps, self.pages),
            "status": final["status_after"],
            "started_ns": 100,
            "finished_ns": 500,
        }
        self.binding = {
            "run_id": self.plan["run_id"],
            "transaction_sha256": "a" * 64,
            "invocation_id": "b" * 32,
            "guardian_pid": 4242,
            "guardian_starttime": 123,
            "startup_deadline_ns": 1000,
        }

    def encode(self, observation=None, clock=lambda: 600, pages=None):
        return codec.encode(
            self.observation if observation is None else observation,
            self.plan,
            self.manifest,
            self.binding,
            self.deps,
            pages=self.pages if pages is None else pages,
            clock=clock,
        )

    def decode(self, data, digest=None, clock=lambda: 600, pages=None):
        return codec.decode(
            data,
            hashlib.sha256(data).hexdigest() if digest is None else digest,
            self.plan,
            self.manifest,
            self.binding,
            self.deps,
            pages=self.pages if pages is None else pages,
            clock=clock,
        )

    def altered(self, edit):
        data, _ = self.encode()
        wire = json.loads(data)
        edit(wire)
        return json.dumps(wire, sort_keys=True, separators=(",", ":")).encode()

    def test_lossless_canonical_round_trip_without_authority(self):
        data, digest = self.encode()
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())
        self.assertEqual(self.decode(data, digest), self.observation)
        self.assertIs(type(self.decode(data)["maps"]), bytes)
        self.assertIs(type(self.decode(data)["python"]["version"]), tuple)
        self.assertLess(len(data), 1024**2)

    def test_mappings_carry_the_root_mount_device_not_the_stat_device(self):
        observation = copy.deepcopy(self.observation)
        # A btrfs subvolume: stat reports its own device, maps the mount's.
        for row in observation["files"].values():
            row["device"] = os.makedev(0, 52)
        data, _ = self.encode(observation)
        self.assertEqual(self.decode(data), observation)
        stat_device = observation["maps"].replace(
            b" %02x:%02x " % self.device, b" 00:34 "
        )
        self.assertNotEqual(stat_device, observation["maps"])
        observation["maps"] = stat_device
        with self.assertRaisesRegex(ValueError, "^runtime mapped file identity$"):
            self.encode(observation)

    def test_mapped_rows_round_trip_and_bind_to_the_callers_pages(self):
        data, _ = self.encode()
        decoded = self.decode(data)
        self.assertIs(type(decoded["mapped"]), tuple)
        self.assertEqual(len(decoded["mapped"]), 2)
        self.assertIs(type(decoded["mapped"][0]["anonymous"]), bytes)
        self.assertEqual(decoded["mapped"], self.observation["mapped"])
        python3 = "/usr/bin/python3"
        other = MappingProxyType(
            {
                **self.pages,
                python3: (hashlib.sha256(b"other").digest(), *self.pages[python3][1:]),
            }
        )
        with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
            self.decode(data, pages=other)
        with self.assertRaisesRegex(ValueError, "^runtime mapped bytes differ$"):
            self.encode(pages=other)
        for pages in (dict(self.pages), {}, ()):
            with (
                self.subTest(pages=type(pages).__name__),
                self.assertRaisesRegex(ValueError, "^runtime page digests$"),
            ):
                self.decode(data, pages=pages)
        for call in (
            lambda: codec.encode(
                self.observation, self.plan, self.manifest, self.binding, self.deps
            ),
            lambda: codec.decode(
                data,
                hashlib.sha256(data).hexdigest(),
                self.plan,
                self.manifest,
                self.binding,
                self.deps,
            ),
        ):
            with self.assertRaises(TypeError):
                call()

    def test_wire_rows_cannot_drop_a_mapping_or_claim_code_pages_copied(self):
        row = self.observation["mapped"][1]
        copied = {
            "$tuple": [
                {
                    "start": row["start"],
                    "end": row["end"],
                    "anonymous": {"$bytes": "01"},
                    "sha256": hashlib.sha256(b"").hexdigest(),
                }
            ]
        }
        for name, edit, error in (
            (
                "dropped",
                lambda wire: wire["observation"]["mapped"]["$tuple"].pop(),
                "^runtime mapped row count$",
            ),
            (
                "copied code",
                lambda wire: wire["observation"]["mapped"]["$tuple"].__setitem__(
                    slice(1, 2), copied["$tuple"]
                ),
                "^runtime anonymous page in executable mapping$",
            ),
            (
                "absent",
                lambda wire: wire["observation"].pop("mapped"),
                "^invalid fields$",
            ),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, error):
                self.decode(self.altered(edit))

    def test_first_witness_scope_is_refused(self):
        data, _ = self.encode()
        self.assertEqual(json.loads(data)["scope"], "contained-job-startup-witness-v2")
        with self.assertRaisesRegex(ValueError, "^startup witness scope or authority$"):
            self.decode(
                self.altered(
                    lambda wire: wire.update(scope="contained-job-startup-witness-v1")
                )
            )

    def test_wrong_hash_binding_or_authority_refuses(self):
        data, _ = self.encode()
        with self.assertRaises(ValueError):
            self.decode(data, "0" * 64)
        for edit in (
            lambda wire: wire["binding"].update(guardian_pid=9999),
            lambda wire: wire.update(native_authorized=True),
            lambda wire: wire.update(full_contract_proven=True),
            lambda wire: wire.update(extra=True),
        ):
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.decode(self.altered(edit))

    def test_late_startup_window_or_completion_refuses(self):
        with self.assertRaises(TimeoutError):
            self.encode(clock=lambda: 1000)
        calls = [0]

        def clock():
            calls[0] += 1
            return 600 if calls[0] < 5 else 1000

        with self.assertRaises(TimeoutError):
            self.encode(clock=clock)

    def test_negative_filesystem_timestamps_and_large_byte_payload_round_trip(self):
        for snapshot in (
            self.observation["initial_filesystem"],
            self.observation["filesystem"],
        ):
            snapshot["nodes"]["/"]["mtime_ns"] = -42
        data, _ = self.encode()
        self.assertEqual(self.decode(data)["filesystem"]["nodes"]["/"]["mtime_ns"], -42)
        timer = codec.Clock(1000, lambda: 600)
        value = b"x" * 5000
        wire = codec.transform(value, codec.Budget(timer))
        self.assertEqual(codec.transform(wire, codec.Budget(timer), decode=True), value)

    def test_canonical_encoding_and_duplicate_keys_are_required(self):
        data, _ = self.encode()
        for candidate in (
            b" " + data,
            data[:-1] + b',"scope":"contained-job-startup-witness-v2"}',
        ):
            with (
                self.subTest(candidate_bytes=len(candidate)),
                self.assertRaises(ValueError),
            ):
                self.decode(candidate)

    def test_reserved_tags_and_noncanonical_hex_refuse(self):
        for value in (
            {"$bytes": "0"},
            {"$bytes": "FF"},
            {"$bytes": "zz"},
            {"$unknown": []},
            {"$tuple": "wrong"},
            {"$bytes": "00", "extra": 1},
        ):
            data = self.altered(
                lambda wire, value=value: wire["observation"].update(maps=value)
            )
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.decode(data)
        bad = dict(self.observation, maps={"$bytes": "00"})
        with self.assertRaises(ValueError):
            self.encode(bad)

    def test_contradictory_core_does_not_use_boolean_integer_equality(self):
        raw = copy.deepcopy(self.observation)
        raw["core"]["fds"] = (False, 1, 2)
        with self.assertRaises(ValueError):
            self.encode(raw)
        data = self.altered(
            lambda wire: wire["binding"].update(guardian_starttime=True)
        )
        with self.assertRaises(ValueError):
            self.decode(data)

    def test_phase_times_and_final_status_must_agree(self):
        for change in (
            "before-first",
            "after-result",
            "different-origin",
            "changed-proc",
            "status",
        ):
            raw = copy.deepcopy(self.observation)
            if change == "before-first":
                raw["filesystem"]["finished_ns"] = 250
            elif change == "after-result":
                raw["filesystem"]["finished_ns"] = 550
            elif change == "different-origin":
                raw["started_ns"] = 101
            elif change == "changed-proc":
                raw["filesystem"]["proc"]["maps"] += b"different\n"
            else:
                raw["status"] = b"different status"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.encode(raw)

    def test_python_maps_and_manifest_policy_is_rechecked(self):
        for change in ("jit", "environment", "maps", "manifest"):
            raw = copy.deepcopy(self.observation)
            if change == "jit":
                raw["python"]["jit_enabled"] = True
            elif change == "environment":
                raw["python"]["environment"]["PATH"] = "/tmp"
            elif change == "maps":
                raw["maps"] = raw["maps"].replace(b"r-xp", b"rwxp", 1)
            else:
                raw["runtime_manifest_sha256"] = "f" * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.encode(raw)

    def test_byte_node_depth_and_text_caps(self):
        with self.assertRaises(ValueError):
            self.decode(b"x" * (codec.LIMIT + 1))
        with self.assertRaises(ValueError):
            self.encode(dict(self.observation, maps=b"x" * (codec.LIMIT // 2 + 1)))
        deep = 0
        for _ in range(codec.MAX_DEPTH + 1):
            deep = [deep]
        for value in (
            deep,
            [0] * (codec.MAX_NODES + 1),
            "x" * 4097,
            2**64,
            -(2**63) - 1,
            1.5,
        ):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                codec.transform(value, codec.Budget(codec.Clock(1000, lambda: 600)))

    def test_expiry_at_serialization_or_decoder_completion_refuses(self):
        clock = [600]
        real = self.deps.preflight.root.closure.canonical

        def late(value):
            result = real(value)
            if (
                type(value) is dict
                and value.get("scope") == "contained-job-startup-witness-v2"
            ):
                clock[0] = 1000
            return result

        with (
            mock.patch.object(
                self.deps.preflight.root.closure, "canonical", side_effect=late
            ),
            self.assertRaises(TimeoutError),
        ):
            self.encode(clock=lambda: clock[0])
        data, _ = self.encode()
        real_validate = codec.validate
        clock[0] = 600

        def late_validate(*args, **kwargs):
            real_validate(*args, **kwargs)
            clock[0] = 1000

        with (
            mock.patch.object(codec, "validate", side_effect=late_validate),
            self.assertRaises(TimeoutError),
        ):
            self.decode(data, clock=lambda: clock[0])

    def test_decoded_observation_does_not_alias_original(self):
        data, _ = self.encode()
        decoded = self.decode(data)
        self.observation["python"]["environment"]["PATH"] = "/changed"
        self.assertEqual(decoded["python"]["environment"]["PATH"], "/usr/bin:/bin")

    def test_original_start_window_clamps_later_binding_deadline(self):
        self.binding["startup_deadline_ns"] = 9_000_000_000
        data, _ = self.encode()
        original = self.deps.runtime_state.check_runtime_state
        for operation in ("encode", "decode"):
            clock = [600]

            def expire(*args, clock=clock):
                original(*args)
                clock[0] = self.observation["started_ns"] + 5_000_000_000

            with (
                mock.patch.object(
                    self.deps.runtime_state, "check_runtime_state", side_effect=expire
                ),
                self.subTest(operation=operation),
                self.assertRaises(TimeoutError),
            ):
                if operation == "encode":
                    self.encode(clock=lambda clock=clock: clock[0])
                else:
                    self.decode(data, clock=lambda clock=clock: clock[0])

    def test_old_witness_at_exact_start_boundary_refuses(self):
        self.binding["startup_deadline_ns"] = 9_000_000_000
        data, _ = self.encode()
        for now in (5_000_000_100, 5_000_000_101):
            with self.subTest(now=now), self.assertRaises(TimeoutError):
                self.encode(clock=lambda now=now: now)
            with self.subTest(now=now), self.assertRaises(TimeoutError):
                self.decode(data, clock=lambda now=now: now)

    def test_aggregate_node_limit_across_small_containers(self):
        value = [[0] * 5 for _ in range(5)]
        with mock.patch.object(codec, "MAX_NODES", 20), self.assertRaises(ValueError):
            codec.transform(value, codec.Budget(codec.Clock(1000, lambda: 600)))

    def test_aggregate_byte_limit_across_individually_valid_strings(self):
        value = ["x" * 3000 for _ in range(3)]
        with mock.patch.object(codec, "LIMIT", 10000), self.assertRaises(ValueError):
            codec.transform(value, codec.Budget(codec.Clock(1000, lambda: 600)))


if __name__ == "__main__":
    unittest.main()

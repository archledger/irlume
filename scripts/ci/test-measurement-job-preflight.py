#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Synthetic complete core witnesses; no runtime admission or service launch."""

import copy
import importlib.util
import os
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


preflight = load("preflight", "measurement-job-preflight.py")
fixtures = load("preflight_fixtures", "test-measurement-job-filesystem.py")


class AdapterTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.FilesystemTests(
            "test_fixed_root_identities_and_special_nodes_are_collected_without_data_io"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.plan, self.bus = fixture.plan, fixture.bus
        self.raw = fixture.collect()
        core = fixtures.fixtures.witness(self.plan)
        self.raw["proc"] = {
            **{
                key: core[key]
                for key in ("namespaces", "uid_map", "gid_map", "status", "fds")
            },
            "root": {key: self.raw["nodes"]["/"][key] for key in ("device", "inode")},
            "status_before": core["status"],
            "maps": b"unvalidated-native-mappings\n",
            "mountinfo": core["mountinfo"],
            "stdio": self.raw["proc"]["stdio"],
            "started_ns": 100,
            "finished_ns": 200,
        }
        self.raw["status_after"] = core["status"]
        self.raw["started_ns"], self.raw["finished_ns"] = 100, 300
        self.raw["nodes"]["/tmp"]["mode"] = 0o41777
        self.raw["volumes"] = {
            "/": {"flags": os.ST_RDONLY, "bytes": 1024**3},
            "/run": {
                "flags": os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC,
                "bytes": 16 * 1024**2,
            },
            "/tmp": {
                "flags": os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC,
                "bytes": 16 * 1024**2,
            },
        }

    def check(self, raw=None, deadline=1000, now=400):
        return preflight.core_witness(
            self.plan, self.bus, self.raw if raw is None else raw, deadline, now
        )

    def test_raw_snapshot_schema_matches_collector_shape(self):
        self.assertIsNone(preflight.check_snapshot(self.plan, self.raw, 1000, 400))

    def test_complete_candidate_includes_explicit_ptmx_without_authority(self):
        before = copy.deepcopy(self.raw)
        row = self.check()
        self.assertEqual(row["denied"]["/dev/ptmx"]["blocked_by"], "/dev/pts")
        self.assertIsNone(row["dev_log"])
        self.assertNotIn("native_authorized", row)
        self.assertEqual(self.raw, before)

    def test_extra_missing_and_wrong_typed_metadata_refuse(self):
        for key, value in (
            ("extra", True),
            ("started_ns", True),
            ("finished_ns", "300"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(dict(self.raw, **{key: value}))
        for key in self.raw:
            bad = copy.deepcopy(self.raw)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.check(bad)
        for field, value in (
            ("mode", True),
            ("inode", 0),
            ("size", -1),
            ("uid", 2**32),
        ):
            bad = copy.deepcopy(self.raw)
            bad["nodes"]["/run/irlume/base.raw"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(bad)
        bad = copy.deepcopy(self.raw)
        bad["nodes"]["/unknown"] = None
        with self.assertRaises(ValueError):
            self.check(bad)

    def test_shared_phase_timestamps_cannot_reset_or_arrive_late(self):
        for changes in (
            {"started_ns": 101},
            {"finished_ns": 199},
            {"finished_ns": 1001},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.check(dict(self.raw, **changes))
        with self.assertRaises(ValueError):
            self.check(deadline=400)
        with self.assertRaises(ValueError):
            self.check(deadline=7_000_000_100, now=6_000_000_100)
        with self.assertRaises(ValueError):
            preflight.check_snapshot(self.plan, self.raw, 7_000_000_100, 6_000_000_100)

    def test_volume_permissions_must_agree_with_mountinfo(self):
        for path, flag in (
            ("/", os.ST_RDONLY),
            ("/run", os.ST_NOSUID),
            ("/tmp", os.ST_NOEXEC),
        ):
            bad = copy.deepcopy(self.raw)
            bad["volumes"][path]["flags"] ^= flag
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.check(bad)

    def test_all_status_samples_and_stdio_access_are_checked(self):
        for field in ("status_before", "status", "status_after"):
            bad = copy.deepcopy(self.raw)
            row = bad if field == "status_after" else bad["proc"]
            row[field] = row[field].replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0")
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(bad)
        bad = copy.deepcopy(self.raw)
        fd, identity, flags = bad["proc"]["stdio"][0]
        bad["proc"]["stdio"] = (
            (fd, identity, flags | os.O_PATH),
            *bad["proc"]["stdio"][1:],
        )
        with self.assertRaises(ValueError):
            self.check(bad)

    def test_inventory_and_ptmx_relationship_cannot_be_fabricated(self):
        for change in (
            "extra-entry",
            "readable-pts",
            "unknown-symlink",
            "missing-device",
        ):
            bad = copy.deepcopy(self.raw)
            if change == "extra-entry":
                bad["entries"]["/run"] += ("secret",)
            elif change == "readable-pts":
                bad["nodes"]["/dev/pts"]["mode"] |= 0o700
            elif change == "unknown-symlink":
                bad["nodes"]["/dev/ptmx"]["target"] = "/outside"
            else:
                bad["nodes"]["/dev/null"] = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(bad)

    def test_low_level_bytes_metadata_and_stdio_boundaries(self):
        for value in (b"", b"x" * 11, "text"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                preflight.check_bytes(value, 10)
        for value in ((), self.raw["proc"]["stdio"][:2], (False, True, None)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                preflight.check_stdio(value)
        bad = copy.deepcopy(self.raw)
        bad["nodes"]["/run/irlume/base.raw"]["mtime_ns"] = True
        with self.assertRaises(ValueError):
            self.check(bad)

    def test_process_root_and_namespace_require_their_independent_witnesses(self):
        bad = copy.deepcopy(self.raw)
        bad["proc"]["root"]["inode"] += 2**32
        with self.assertRaises(ValueError):
            self.check(bad)
        bad = copy.deepcopy(self.raw)
        bad["proc"]["namespaces"]["net"] = self.plan["host_namespaces"]["net"]
        with self.assertRaises(ValueError):
            self.check(bad)

    def test_returned_witness_does_not_alias_mutable_snapshot_dictionaries(self):
        row = self.check()
        saved = copy.deepcopy(row)
        self.raw["proc"]["namespaces"]["net"] = 1
        self.raw["nodes"]["/dev/pts"]["mode"] |= 0o777
        self.assertEqual(row, saved)

    def test_kernel_view_node_needs_its_cover_and_stacking_refuses_first(self):
        self.assertEqual(self.raw["nodes"]["/sys/kernel/debug"]["mode"], 0o40000)
        lines = self.raw["proc"]["mountinfo"].splitlines(keepends=True)
        bad = copy.deepcopy(self.raw)
        bad["proc"]["mountinfo"] = b"".join(
            line for line in lines if b" /sys/kernel/debug " not in line
        )
        with self.assertRaisesRegex(ValueError, "kernel cover and node disagree"):
            self.check(bad)
        tmp = next(line for line in lines if b" /tmp " in line)
        number = tmp.split(b" ")[0]
        stacked = tmp.replace(number + b" ", b"99 ", 1).replace(
            b" " + tmp.split(b" ")[1] + b" ", b" " + number + b" ", 1
        )
        bad = copy.deepcopy(self.raw)
        bad["proc"]["mountinfo"] += stacked
        # Refused by the mount tree before the volume flags are compared.
        bad["volumes"]["/tmp"]["flags"] ^= os.ST_NOEXEC
        with self.assertRaisesRegex(ValueError, "stacked mount: /tmp"):
            self.check(bad)

    def test_snapshot_parent_types_and_inventory_order_are_checked_directly(self):
        bad = copy.deepcopy(self.raw)
        bad["nodes"]["/sys/fs"]["mode"] = 0o100400
        with self.assertRaises(ValueError):
            preflight.check_snapshot(self.plan, bad, 1000, 400)
        bad = copy.deepcopy(self.raw)
        bad["entries"]["/run"] = tuple(reversed(bad["entries"]["/run"]))
        with self.assertRaises(ValueError):
            preflight.check_snapshot(self.plan, bad, 1000, 400)


if __name__ == "__main__":
    unittest.main()

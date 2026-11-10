# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
import copy
import json
import sys
import unittest

import harness
import request_contract


def report(kind="would_grant"):
    return {
        "schema": 1,
        "operation": "ir_request_evaluation",
        "phase": "evaluation",
        "authentication_granted": False,
        "result": {"kind": kind, "identity_acceptance": "both"},
        "scope": "primary",
        "window_ms": 15000,
        "elapsed_ms": 20,
        "initialization_ms": 100,
        "counts": dict(zip(request_contract.COUNTS, [1] * 5)),
        "timings_ms": dict(zip(request_contract.TIMINGS, [1] * 5)),
    }


class ContractTests(unittest.TestCase):
    def test_real_traced_request_requires_process_success_and_correct_mode(self):
        record = report()
        record.update(phase="preflight", result={"kind": "ready"})
        record["counts"] = dict.fromkeys(record["counts"], 0)
        record["timings_ms"] = dict.fromkeys(record["timings_ms"], None)
        for exit_code in (0, 1):
            code = f"import sys; print({json.dumps(record)!r}); sys.exit({exit_code})"
            got = harness.run_traced(
                [sys.executable, "-c", code], request_mode=True, timeout=5
            )
            got["installed_unchanged"] = True
            self.assertEqual(got["report"], record)
            self.assertEqual(
                harness.trial_checks(
                    got, "preflight", request_mode=True, expected_window_ms=15000
                ),
                exit_code == 0,
            )
            self.assertFalse(
                harness.trial_checks(
                    got, "preflight", request_mode=True, expected_window_ms=5000
                )
            )
            self.assertFalse(
                harness.trial_checks(
                    got, "genuine", request_mode=True, expected_window_ms=15000
                )
            )

    def test_real_traced_request_rejects_duplicate_fields(self):
        text = json.dumps(report()).replace('"schema": 1', '"schema": 1, "schema": 1')
        got = harness.run_traced(
            [sys.executable, "-c", f"print({text!r})"], request_mode=True, timeout=5
        )
        self.assertFalse(got["output_valid"])
        self.assertIsNone(got["report"])

    def test_request_topology_accepts_only_exact_production_layouts(self):
        def node(index, name, device, interface="/sys/devices/shared"):
            return {
                "index": index,
                "name": name,
                "device": device,
                "interface": interface,
            }

        members = {
            "video0": node(0, "rgb", "81:0"),
            "video1": node(1, "rgb", "81:1"),
            "video2": node(2, "ir", "81:2"),
            "video3": node(3, "ir", "81:3"),
        }
        cameras = {"rgb": "/dev/video0", "ir": "/dev/video2", "metadata": "/dev/video3"}
        nodes = {
            "rgb": members["video0"],
            "ir": members["video2"],
            "metadata": members["video3"],
        }
        self.assertTrue(request_contract.qualified_topology(nodes, cameras, members))
        for field, value in (
            ("index", 4),
            ("name", "wrong"),
            ("device", "81:0"),
            ("interface", "/sys/devices/virtual/x"),
        ):
            changed = copy.deepcopy(members)
            changed["video1"][field] = value
            self.assertFalse(
                request_contract.qualified_topology(nodes, cameras, changed)
            )
        ir = node(0, "ir", "81:2", "/sys/devices/separate-ir")
        nodes = {"rgb": members["video0"], "ir": ir}
        cameras["metadata"] = None
        self.assertTrue(
            request_contract.qualified_topology(nodes, cameras, {"video2": ir})
        )
        self.assertFalse(
            request_contract.qualified_topology(
                nodes, cameras, {"video2": ir, "video3": members["video3"]}
            )
        )

    def test_mode_cannot_accept_the_other_report_namespace(self):
        with self.assertRaises(ValueError):
            harness.checked_report(report())
        self.assertEqual(harness.checked_report(report(), request_mode=True), report())

    def test_exact_closed_success_and_refusal_shapes(self):
        for scope in ("primary", "secondary"):
            record = report()
            record["scope"] = scope
            self.assertEqual(request_contract.checked_report(record), record)
        for cause in request_contract.CAUSES:
            record = report()
            record["result"] = {"kind": "refused", "cause": cause}
            request_contract.checked_report(record)

    def test_rejects_forged_private_unknown_and_inconsistent_fields(self):
        mutations = [
            ("authentication_granted", True),
            ("schema", True),
            ("schema", 2),
            ("operation", "ir_only_evaluation"),
            ("phase", "preflight"),
            ("scope", None),
            ("score", 0.99),
            ("window_ms", True),
            ("elapsed_ms", -1),
            ("elapsed_ms", float("nan")),
            ("result", {"kind": "ready"}),
            ("result", {"kind": "would_grant", "identity_acceptance": "unknown"}),
            (
                "result",
                {"kind": "refused", "cause": "no_face", "identity_acceptance": "both"},
            ),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                request_contract.checked_report(dict(report(), **{key: value}))
        for key, value in (
            ("captures", 0),
            ("identity", 2),
            ("pad", True),
            ("assessments", 1_000_001),
        ):
            record = copy.deepcopy(report())
            record["counts"][key] = value
            with self.assertRaises(ValueError):
                request_contract.checked_report(record)

    def test_preflight_has_no_assessment_or_capture(self):
        record = report()
        record.update(phase="preflight", result={"kind": "ready"})
        record["counts"] = dict(zip(request_contract.COUNTS, [0] * 5))
        record["timings_ms"] = dict(
            zip(request_contract.TIMINGS, [1, None, None, None, None])
        )
        request_contract.checked_report(record)
        record["counts"]["assessments"] = 1
        with self.assertRaises(ValueError):
            request_contract.checked_report(record)


if __name__ == "__main__":
    unittest.main()

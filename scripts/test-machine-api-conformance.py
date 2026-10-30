#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Contract regressions that do not require a camera or running daemon."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "conformance", ROOT / "scripts/machine-api-conformance.py"
)
CONFORMANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFORMANCE)


def fixture(name):
    return json.loads((ROOT / "schemas/fixtures/v1" / name).read_text())


class ContractTests(unittest.TestCase):
    def test_status_observation_fields_are_optional_booleans(self):
        validate, note = CONFORMANCE.load_validator(
            ROOT / "schemas/machine-api-v1.schema.json", strict=True
        )
        self.assertIsNotNone(validate, note)
        original = fixture("status-daemon-running.json")
        self.assertEqual(validate(original), [])
        for parent, key in [("camera", "known"), (None, "fingerprint_known")]:
            for value in [True, False, None, 0, "false", [], {}]:
                with self.subTest(field=key, value=value):
                    document = copy.deepcopy(original)
                    target = document["data"][parent] if parent else document["data"]
                    target[key] = value
                    self.assertEqual(not validate(document), isinstance(value, bool))
        original["data"]["undocumented"] = True
        self.assertTrue(validate(original))

    def test_recognizer_selection_is_an_optional_closed_enum(self):
        # Contract 1 permits added fields, not new enum values: a selection
        # word the schema does not list must fail a consumer's permissive
        # validator as well as the engine's strict one (#1053). The release
        # captures predate the field, so the shapes the CLI writes for a
        # non-root peer of a default build are added to them here.
        status = fixture("status-daemon-running-0.15.0.json")
        status["data"]["recognizer"] = {
            "device": "cpu", "known": True,
            "reason": "NPU discovery not reported; using CPU", "selection": "auto",
        }
        doctor = fixture("doctor-0.15.0.json")
        doctor["data"]["checks"] += [
            {"detail": "CPU: NPU discovery not reported; using CPU",
             "id": "recognizer-device", "state": "info"},
            {"detail": "auto; only a certified device can take the recognizer off CPU",
             "id": "recognizer-selection", "state": "info"},
        ]
        for strict in [False, True]:
            validate, note = CONFORMANCE.load_validator(
                ROOT / "schemas/machine-api-v1.schema.json", strict=strict
            )
            self.assertIsNotNone(validate, note)
            with self.subTest(strict=strict, document="doctor"):
                self.assertEqual(validate(doctor), [])
            for value in ["auto", "cpu", "npu", "gpu", "tpu", "AUTO", "", None, 0, []]:
                with self.subTest(strict=strict, value=value):
                    document = copy.deepcopy(status)
                    document["data"]["recognizer"]["selection"] = value
                    self.assertEqual(
                        not validate(document), value in ["auto", "cpu", "npu"]
                    )
            # Absent when the daemon did not report one.
            document = copy.deepcopy(status)
            del document["data"]["recognizer"]["selection"]
            self.assertEqual(validate(document), [])

    def test_recognizer_fields_are_optional_and_closed(self):
        # These are the shapes the CLI writes for each placement, added to the
        # 0.15.0 capture, which predates them. The GPU fields and word of a
        # nightly build are gone (ADR-0038): --strict refuses them.
        status = fixture("status-daemon-running-0.15.0.json")
        npu = {
            "known": True, "device": "npu",
            "platform": "ab12", "runtime_available": True, "qualified": True,
            "selection": "auto",
            "selection_provenance": {"source": "default", "issue": "none"},
        }
        placements = {
            "npu": npu,
            "older-daemon": {
                "known": True, "device": "cpu",
                "reason": "NPU discovery not reported; using CPU", "selection": "auto",
            },
            "unreported": {"known": False},
        }
        for strict in [False, True]:
            validate, note = CONFORMANCE.load_validator(
                ROOT / "schemas/machine-api-v1.schema.json", strict=strict
            )
            self.assertIsNotNone(validate, note)

            def with_recognizer(recognizer):
                document = copy.deepcopy(status)
                document["data"]["recognizer"] = recognizer
                return document

            for name, recognizer in placements.items():
                with self.subTest(strict=strict, placement=name):
                    self.assertEqual(validate(with_recognizer(recognizer)), [])
            # `device` stays the two words contract 1 names.
            for value in ["cpu", "npu", "gpu", "GPU", "tpu", "", None, 0]:
                with self.subTest(strict=strict, field="device", value=value):
                    document = with_recognizer(dict(npu, device=value))
                    self.assertEqual(not validate(document), value in ["cpu", "npu"])
            # The recognizer object is described, so --strict closes it.
            for field in [
                "undocumented", "accelerator", "gpu_platform",
                "gpu_runtime_available", "gpu_qualified",
            ]:
                with self.subTest(strict=strict, field=field):
                    document = with_recognizer(dict(npu, **{field: True}))
                    self.assertEqual(not validate(document), not strict)

    def test_doctor_recognizer_rows_validate_in_info_and_unknown_states(self):
        # The five rows `doctor` writes from the daemon's Health answer, in
        # each branch's states: an answer with an NPU placement, an answer from
        # an older daemon, a Health without the report, and no answer. The last
        # two give only the first row a detail.
        rows = [
            "recognizer-device", "recognizer-selection", "npu-runtime",
            "npu-qualification", "npu-platform",
        ]

        def answered(*details):
            return [
                {"id": row, "state": state, "detail": detail}
                for row, (state, detail) in zip(rows, details, strict=True)
            ]

        def unanswered(detail):
            return [{"id": rows[0], "state": "unknown", "detail": detail}] + [
                {"id": row, "state": "unknown"} for row in rows[1:]
            ]

        cases = {
            "npu-placement": answered(
                ("info", "NPU"),
                ("info", "npu; admission and certification still decide; "
                         "source: settings; issue: none"),
                ("info", "available to this engine; NPU discovery succeeded"),
                ("info", "qualified for this engine's NPU placement"),
                ("info", "ab12"),
            ),
            "older-daemon": answered(
                ("info", "CPU: NPU discovery not reported; using CPU"),
                ("info", "auto; only a certified device can take the recognizer "
                         "off CPU; source not reported"),
                ("unknown", "runtime discovery was not attempted or reported"),
                ("unknown", "no model qualification was reported"),
                ("info", "no NPU platform identity was read"),
            ),
            "predates-report": unanswered("the daemon predates this report"),
            "no-answer": unanswered("the daemon did not answer"),
        }
        base = fixture("doctor-0.15.0.json")
        self.assertFalse({check["id"] for check in base["data"]["checks"]} & set(rows))

        def with_rows(checks):
            document = copy.deepcopy(base)
            document["data"]["checks"] += copy.deepcopy(checks)
            return document

        for strict in [False, True]:
            validate, note = CONFORMANCE.load_validator(
                ROOT / "schemas/machine-api-v1.schema.json", strict=strict
            )
            self.assertIsNotNone(validate, note)
            for name, checks in cases.items():
                with self.subTest(strict=strict, case=name):
                    self.assertEqual(sorted(c["id"] for c in checks), sorted(rows))
                    self.assertEqual(validate(with_rows(checks)), [])
                # Each row is checked: a state outside the enum or a null
                # detail fails both validators, an undocumented member only
                # the strict one.
                for index, row in enumerate(rows):
                    for change, valid in [
                        ({"state": "ok"}, False),
                        ({"state": None}, False),
                        ({"detail": None}, False),
                        ({"undocumented": True}, not strict),
                    ]:
                        with self.subTest(strict=strict, case=name, row=row, change=change):
                            changed = copy.deepcopy(checks)
                            changed[index].update(change)
                            self.assertEqual(not validate(with_rows(changed)), valid)

    def test_census_allows_only_documented_video_node_fields(self):
        document = fixture("camera-census.json")
        original = copy.deepcopy(document)
        self.assertEqual(CONFORMANCE.forbidden_paths(document, "camera-census"), [])
        self.assertEqual(document, original)
        self.assertEqual(
            CONFORMANCE.forbidden_paths(document, "status-json"), ["/dev/video"]
        )
        for key in ["note", "unexpected"]:
            with self.subTest(key=key):
                changed = copy.deepcopy(document)
                changed["data"]["entries"][0][key] = "/dev/video0"
                self.assertEqual(
                    CONFORMANCE.forbidden_paths(changed, "camera-census"), ["/dev/video"]
                )

    def test_census_does_not_allow_pam_paths_or_malformed_nodes(self):
        for path in ["/etc/pam.d/login", "/usr/lib/pam.d/login", "/dev/video0/secret"]:
            with self.subTest(path=path):
                document = fixture("camera-census.json")
                document["data"]["entries"][0]["node"] = path
                self.assertTrue(CONFORMANCE.forbidden_paths(document, "camera-census"))

    def test_census_error_does_not_allow_device_paths(self):
        document = {"command": "camera.census", "ok": False,
                    "error": {"detail": "/dev/video0"}}
        self.assertEqual(
            CONFORMANCE.forbidden_paths(document, "camera-census"), ["/dev/video"]
        )


if __name__ == "__main__":
    unittest.main()

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
                        not validate(document), value in ["auto", "cpu", "npu", "gpu"]
                    )
            # Absent when the daemon did not report one.
            document = copy.deepcopy(status)
            del document["data"]["recognizer"]["selection"]
            self.assertEqual(validate(document), [])

    def test_recognizer_gpu_fields_are_optional_and_closed(self):
        # ADR-0033 phase 3 adds fields, not enum values: a GPU placement keeps
        # `device` cpu with its fixed reason and names the GPU in
        # `accelerator`, and a daemon older than GPU reporting sends none of
        # the new fields (MACHINE-API.md). These are the shapes the CLI writes
        # for each, added to the 0.15.0 capture, which predates them.
        status = fixture("status-daemon-running-0.15.0.json")
        gpu = {
            "known": True, "device": "cpu",
            "reason": "the recognizer runs on the GPU (accelerator: gpu); "
                      "CPU stays the reference",
            "selection": "gpu",
            "selection_provenance": {"source": "settings", "issue": "none"},
            "accelerator": "gpu", "gpu_platform": "cd34",
            "gpu_runtime_available": True, "gpu_qualified": True,
        }
        placements = {
            "gpu": gpu,
            "npu": {
                "known": True, "device": "npu", "accelerator": "npu",
                "platform": "ab12", "runtime_available": True, "qualified": True,
                "selection": "auto",
                "selection_provenance": {"source": "default", "issue": "none"},
            },
            "older-daemon": {
                "known": True, "device": "cpu",
                "reason": "NPU discovery not reported; using CPU", "selection": "auto",
            },
            "unreported": {"known": False},
        }
        gpu_fields = [
            "accelerator", "gpu_platform", "gpu_runtime_available", "gpu_qualified"
        ]

        def one_of(*words):
            return lambda value: isinstance(value, str) and value in words

        def boolean(value):
            return isinstance(value, bool)

        # Each value replaces the field in the GPU placement. `device` stays
        # the two words contract 1 names, so `gpu` there is rejected, and
        # `accelerator` is absent on CPU rather than `cpu`.
        cases = [
            ("device", ["cpu", "npu", "gpu", "GPU", "tpu", "", None, 0],
             one_of("cpu", "npu")),
            ("accelerator", ["gpu", "npu", "cpu", "GPU", "NPU", "tpu", "", None, 0],
             one_of("gpu", "npu")),
            ("gpu_runtime_available",
             [True, False, None, 0, 1, "true", "false", [], {}], boolean),
            ("gpu_qualified", [True, False, None, 0, 1, "true", "false", [], {}], boolean),
            ("gpu_platform", ["cd34", None, 0, True, [], {}],
             lambda value: isinstance(value, str)),
        ]
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
            for field, values, accepted in cases:
                for value in values:
                    with self.subTest(strict=strict, field=field, value=value):
                        document = with_recognizer(dict(gpu, **{field: value}))
                        self.assertEqual(not validate(document), accepted(value))
            # Every GPU field is optional: an older daemon omits it.
            for field in gpu_fields:
                with self.subTest(strict=strict, absent=field):
                    recognizer = dict(gpu)
                    del recognizer[field]
                    self.assertEqual(validate(with_recognizer(recognizer)), [])
            # The recognizer object is described, so --strict closes it.
            with self.subTest(strict=strict, field="undocumented"):
                document = with_recognizer(dict(gpu, undocumented=True))
                self.assertEqual(not validate(document), not strict)

    def test_doctor_recognizer_rows_validate_in_info_and_unknown_states(self):
        # The eight rows `doctor` writes from the daemon's Health answer, in
        # each branch's states: an answer with a GPU placement, an answer from
        # a daemon older than GPU reporting, a Health without the report, and
        # no answer. The last two give only the first row a detail.
        rows = [
            "recognizer-device", "recognizer-selection", "npu-runtime",
            "npu-qualification", "npu-platform", "gpu-runtime",
            "gpu-qualification", "gpu-platform",
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
            "gpu-placement": answered(
                ("info", "GPU"),
                ("info", "gpu; no build admits GPU placement yet; "
                         "source: settings; issue: none"),
                ("unknown", "runtime discovery was not attempted or reported"),
                ("unknown", "no model qualification was reported"),
                ("info", "no NPU platform identity was read"),
                ("info", "available to this engine; GPU discovery succeeded"),
                ("info", "qualified for this engine's GPU placement"),
                ("info", "cd34"),
            ),
            "older-daemon": answered(
                ("info", "CPU: NPU discovery not reported; using CPU"),
                ("info", "auto; only a certified device can take the recognizer "
                         "off CPU; source not reported"),
                ("unknown", "runtime discovery was not attempted or reported"),
                ("unknown", "no model qualification was reported"),
                ("info", "no NPU platform identity was read"),
                ("unknown", "GPU discovery was not attempted or reported"),
                ("unknown", "no GPU qualification was reported"),
                ("info", "no GPU platform identity was read"),
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

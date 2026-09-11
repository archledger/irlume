#!/usr/bin/env python3
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

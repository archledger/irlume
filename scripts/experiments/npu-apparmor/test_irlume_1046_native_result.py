import json
import unittest

from irlume_1046_native_result import parse_native_result, require_single_test


class ResultTests(unittest.TestCase):
    def test_single_control_summary_is_accepted(self):
        output = (
            "NATIVE_AA_DENIAL_CONTROL pid=123 tid=124\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "415 filtered out; finished in 0.00s\n"
        )
        require_single_test(output, 0)

    def test_missing_duplicate_and_incomplete_summaries_are_rejected(self):
        good = (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "415 filtered out; finished in 0.00s\n"
        )
        for output, code in (
            ("NATIVE_AA_DENIAL_CONTROL pid=123 tid=124", 0),
            (good + good, 0),
            (good.replace("1 passed", "0 passed"), 0),
            (good.replace("0 ignored", "1 ignored"), 0),
            (good, 1),
        ):
            with self.subTest(output=output, code=code), self.assertRaises(ValueError):
                require_single_test(output, code)

    def good(self):
        return {
            "case": "bin-native",
            "scope": "test-only-native",
            "executable": "/usr/bin/irlumed",
            "label": "irlumed (enforce)",
            "pid": 123,
            "pci_id": "8086:643e",
            "firmware": "real build",
            "library": "/usr/lib64/libopenvino_c.so.2621",
            "model_sha256": "a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60",
            "identity_digest": "a" * 64,
            "execution_digest": "b" * 64,
            "cpu_reference_digest": "c" * 64,
            "execution_device": "NPU",
            "native_inferences": 6,
            "markers_absent": True,
            "raw_output_digests": ["d" * 64] * 3,
            "synthetic_distances": [0.001] * 6,
        }

    def output(self, data):
        return (
            "NATIVE_AA_RESULT "
            + json.dumps(data)
            + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 395 filtered out; finished in 1.0s\n"
        )

    def test_accepts_only_complete_native_evidence(self):
        self.assertEqual(
            parse_native_result(self.output(self.good()), 0, "bin-native"), self.good()
        )

    def test_refuses_failed_or_vacuous_test_runs(self):
        for output, code in [
            (self.output(self.good()), 1),
            ("test result: ok. 0 passed; 0 failed;", 0),
            (self.output(self.good()).replace("0 ignored", "1 ignored"), 0),
        ]:
            with self.assertRaises(ValueError):
                parse_native_result(output, code, "bin-native")

    def test_refuses_fallback_firmware_and_missing_evidence(self):
        for field, value in [
            ("execution_device", "CPU"),
            ("firmware", "unverified"),
            ("label", "unconfined"),
            ("native_inferences", 0),
            ("pid", 0),
            ("markers_absent", False),
            ("synthetic_distances", [float("nan")] * 6),
            ("synthetic_distances", [0.02] * 6),
            ("raw_output_digests", []),
            ("pci_id", "other"),
        ]:
            data = self.good()
            data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse_native_result(self.output(data), 0, "bin-native")

    def test_duplicate_or_wrong_case_results_are_rejected(self):
        text = self.output(self.good())
        for output, case in [(text + text, "bin-native"), (text, "local-native")]:
            with self.assertRaises(ValueError):
                parse_native_result(output, 0, case)


if __name__ == "__main__":
    unittest.main()

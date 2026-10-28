import json
import unittest

from irlume_1046_native_audit import validate_window


class AuditWindowTests(unittest.TestCase):
    def denied(self, *, pid=124, profile="irlumed", path="/opt/irlume-aa-denied"):
        return json.dumps(
            {
                "_TRANSPORT": "kernel",
                "MESSAGE": f'apparmor="DENIED" profile="{profile}" pid={pid} name="{path}"',
            }
        )

    def test_native_window_accepts_no_denials(self):
        self.assertEqual(validate_window(json.dumps({"MESSAGE": "ordinary log"})), [])

    def test_control_accepts_exact_process_pid_profile_and_path(self):
        line = self.denied()
        self.assertEqual(
            validate_window(line, control_pid=124), [json.loads(line)["MESSAGE"]]
        )

    def test_control_rejects_a_different_process(self):
        with self.assertRaises(ValueError):
            validate_window(self.denied(pid=123), control_pid=124)

    def test_control_rejects_expected_plus_unrelated_denial(self):
        for extra in [
            self.denied(profile="other"),
            self.denied(path="/other"),
            self.denied(pid=999),
        ]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                validate_window(self.denied() + "\n" + extra, control_pid=124)

    def test_native_window_rejects_other_profile_denials(self):
        with self.assertRaises(ValueError):
            validate_window(self.denied(profile="other"))

    def test_control_requires_a_denial(self):
        with self.assertRaises(ValueError):
            validate_window("", control_pid=124)

    def test_unreadable_message_encoding_is_not_silently_ignored(self):
        with self.assertRaises(TypeError):
            validate_window(json.dumps({"MESSAGE": [255]}))

    def test_application_text_cannot_impersonate_a_kernel_denial(self):
        row = json.loads(self.denied())
        row["_TRANSPORT"] = "stdout"
        with self.assertRaises(ValueError):
            validate_window(json.dumps(row), control_pid=124)


if __name__ == "__main__":
    unittest.main()

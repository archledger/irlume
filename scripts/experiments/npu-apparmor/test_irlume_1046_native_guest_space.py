import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "native_guest_space", Path(__file__).with_name("irlume-1046-native-guest.py")
)
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class GuestSpaceTests(unittest.TestCase):
    def test_two_gib_free_is_accepted_and_recorded(self):
        usage = SimpleNamespace(total=6 * 1024**3, free=2 * 1024**3)
        with patch.object(guest.shutil, "disk_usage", return_value=usage):
            self.assertEqual(
                guest.check_install_space(),
                {
                    "total_bytes": usage.total,
                    "free_bytes": usage.free,
                    "required_free_bytes": 2 * 1024**3,
                },
            )

    def test_insufficient_space_is_rejected(self):
        for free in (0, 16_814_080, 2 * 1024**3 - 1):
            with (
                self.subTest(free=free),
                patch.object(
                    guest.shutil,
                    "disk_usage",
                    return_value=SimpleNamespace(total=3 * 1024**3, free=free),
                ),
                self.assertRaisesRegex(RuntimeError, "guest root free space"),
            ):
                guest.check_install_space()

    def test_no_payload_read_or_install_before_space_admission(self):
        with (
            patch.object(
                guest.shutil,
                "disk_usage",
                return_value=SimpleNamespace(total=3 * 1024**3, free=16_814_080),
            ),
            patch.object(guest, "save") as save,
            patch.object(Path, "read_text") as read,
            patch.object(guest.shutil, "copyfile") as copy,
            self.assertRaisesRegex(RuntimeError, "guest root free space"),
        ):
            guest.install()
        read.assert_not_called()
        copy.assert_not_called()
        save.assert_not_called()


if __name__ == "__main__":
    unittest.main()

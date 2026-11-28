import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from run_guest import check_receipt, qemu_args, run_guest, verify_build


NONCE = "f00dbeef00112233445566778899aabb"
PID = f"BOOK2_BOOT_V1 {NONCE} PID1"
SMOKE = f"BOOK2_BOOT_V1 {NONCE} SMOKE_ONLY"
GOOD = f"[    0.000000] Linux version 7.3.5\r\n{PID}\r\n{SMOKE}\r\n"


class ReceiptTests(unittest.TestCase):
    def test_zero_exit_without_receipt_fails(self):
        self.assertEqual(check_receipt(GOOD, NONCE, "smoke", 0), ("PID1", "SMOKE_ONLY"))
        for text, code in (("", 0), (GOOD, 1), (PID + "\n", 0)):
            with self.assertRaises(ValueError):
                check_receipt(text, NONCE, "smoke", code)

    def test_wrong_nonce_or_order_fails(self):
        for text in (GOOD.replace(NONCE, "0" * 32), f"{SMOKE}\n{PID}\n", GOOD + f"{PID}\n"):
            with self.assertRaises(ValueError):
                check_receipt(text, NONCE, "smoke", 0)

    def test_success_prefix_followed_by_error_fails(self):
        for error in (
            "Kernel panic - not syncing: fixture",
            "Oops: 0000 [#1]",
            f"BOOK2_BOOT_V1 {NONCE} ERROR",
        ):
            with self.assertRaises(ValueError):
                check_receipt(GOOD + error + "\n", NONCE, "smoke", 0)

    def test_unsafe_launch_options_are_absent(self):
        args = qemu_args(Path("/tmp/opencode/k"), Path("/tmp/opencode/c"),
                         Path("/tmp/opencode/serial.log"), "smoke", NONCE)
        self.assertEqual(args, [
            "/usr/bin/qemu-system-x86_64", "-machine", "q35,accel=tcg", "-m", "512", "-smp", "1",
            "-nodefaults", "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
            "-kernel", "/tmp/opencode/k", "-initrd", "/tmp/opencode/c",
            "-serial", "file:/tmp/opencode/serial.log", "-append",
            f"console=ttyS0 rdinit=/init panic=-1 book2_case=smoke book2_nonce={NONCE}",
        ])
        with self.assertRaises(ValueError):
            qemu_args(Path("/tmp/opencode/k"), Path("/tmp/opencode/c"),
                      Path("/tmp/opencode/serial,append=on"), "smoke", NONCE)

    def test_verify_build_refuses_corruption_and_swapped_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            names = ("bzImage", "initramfs.cpio")
            for name in names:
                (root / name).write_bytes(name.encode())
            (root / "build.sha256").write_text("".join(
                f"{hashlib.sha256(name.encode()).hexdigest()}  {name}\n" for name in names
            ))
            self.assertEqual(verify_build(root), tuple(root / n for n in names))
            for replacement in (b"modified kernel", b"initramfs.cpio"):
                (root / "bzImage").write_bytes(replacement)
                with self.assertRaises(ValueError):
                    verify_build(root)

    def test_refuses_elevated_host_before_any_build_read(self):
        with patch("run_guest.os.geteuid", return_value=0):
            with patch("run_guest.verify_build", side_effect=ValueError("unexpected build read")) as read:
                with self.assertRaisesRegex(ValueError, "ordinary host user"):
                    run_guest(Path("/tmp/opencode/build"), Path("/tmp/opencode/receipt"), "smoke")
                read.assert_not_called()

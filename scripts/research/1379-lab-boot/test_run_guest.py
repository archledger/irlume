import hashlib
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from run_guest import QEMU, VERSION, POLICY_EVENTS, check_receipt, qemu_args, run_guest, verify_build


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

    def test_embedded_line_separators_cannot_mint_receipt_lines(self):
        banner = "[    0.000000] Linux version 7.3.5\r\n"
        for sep in ("\r", "\x0b", "\x0c", "\x1c", "\x85", "\u2028"):
            with self.assertRaisesRegex(ValueError, "control character"):
                check_receipt(f"{banner}{PID}{sep}{SMOKE}\r\n", NONCE, "smoke", 0)
            logged = f"{banner}{PID}\r\n[    1.000000] x{sep}{SMOKE}\r\n{SMOKE}\r\n"
            self.assertEqual(check_receipt(logged, NONCE, "smoke", 0), ("PID1", "SMOKE_ONLY"))

    def test_serial_log_is_read_without_newline_translation(self):
        def boot(args, **_):
            if tuple(args) == (QEMU, "--version"):
                return subprocess.CompletedProcess(args, 0, stdout=VERSION + "\n")
            nonce = re.search(r"book2_nonce=([0-9a-f]{32})", args[-1])[1]
            serial = Path(args[args.index("-serial") + 1].removeprefix("file:"))
            serial.write_bytes(f"BOOK2_BOOT_V1 {nonce} PID1\rBOOK2_BOOT_V1 {nonce} SMOKE_ONLY\r\n".encode())
            return subprocess.CompletedProcess(args, 0)

        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temp:
            root = Path(temp)
            images = (root / "bzImage", root / "initramfs.cpio")
            with patch("run_guest.verify_build", return_value=images), \
                    patch("run_guest.subprocess.run", side_effect=boot):
                with self.assertRaisesRegex(ValueError, "control character"):
                    run_guest(root, root / "receipt", "smoke")

    def test_unsafe_launch_options_are_absent(self):
        args = qemu_args(Path("/tmp/opencode/k"), Path("/tmp/opencode/c"),
                         Path("/tmp/opencode/serial.log"), "smoke", NONCE)
        self.assertEqual(args, [
            "/usr/bin/qemu-system-x86_64", "-machine", "q35,accel=tcg", "-m", "512", "-smp", "1",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none", "-nic", "none",
            "-no-reboot", "-kernel", "/tmp/opencode/k", "-initrd", "/tmp/opencode/c",
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

    def test_missing_initial_policy_cannot_count_as_identification(self):
        refused = f"{PID}\nBOOK2_BOOT_V1 {NONCE} REFUSED_NO_INITIAL_POLICY\n"
        self.assertNotIn("DUMMY_IDENTIFIED", check_receipt(refused, NONCE, "missing-deny", 0))
        with self.assertRaises(ValueError):
            check_receipt(refused + f"BOOK2_BOOT_V1 {NONCE} DUMMY_IDENTIFIED\n",
                          NONCE, "missing-deny", 0)

    def test_retained_handle_is_not_a_completed_boundary(self):
        refused = POLICY_EVENTS + ("REFUSED_RETAINED_HANDLE",)
        text = "".join(f"BOOK2_BOOT_V1 {NONCE} {event}\n" for event in refused)
        self.assertEqual(check_receipt(text, NONCE, "kept-fd", 0), refused)
        with self.assertRaises(ValueError):
            check_receipt(text, NONCE, "boundary", 0)

    def test_boundary_requires_independent_proc_and_ipc_controls(self):
        older = POLICY_EVENTS + (
            "INHERITED_HANDLE_CLOSED", "PEER_HANDLE_DENIED", "FD_IPC_DENIED", "BOOT_BOUNDARY_PASS",
        )
        for missing in (None, "PEER_PROC_LINK_DENIED", "FD_IPC_POSITIVE"):
            control = POLICY_EVENTS + (
                "INHERITED_HANDLE_CLOSED", "PEER_PROC_LINK_DENIED", "PEER_HANDLE_DENIED",
                "FD_IPC_POSITIVE", "FD_IPC_DENIED", "BOOT_BOUNDARY_PASS",
            )
            events = older if missing is None else tuple(e for e in control if e != missing)
            text = "".join(f"BOOK2_BOOT_V1 {NONCE} {event}\n" for event in events)
            with self.assertRaises(ValueError):
                check_receipt(text, NONCE, "boundary", 0)

    def test_failed_source_status_is_not_clean(self):
        lab = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temp:
            root = Path(temp)
            commands = root / "bin"
            commands.mkdir()
            source = root / "source"
            source.mkdir()
            git = commands / "git"
            git.write_text("#!/bin/sh\ncase \"$3\" in\n"
                           "rev-parse) echo 988117cc1bb17338c586a4e21ade88b5397eac33;;\n"
                           "status) exit 128;;\n*) exit 1;;\nesac\n")
            git.chmod(0o700)
            result = subprocess.run(
                ("/usr/bin/bash", str(lab / "build_guest.sh"), str(source), str(root / "build")),
                text=True, capture_output=True, timeout=8,
                env={**os.environ, "PATH": f"{commands}:/usr/bin"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("could not verify Linux source cleanliness", result.stderr)
            self.assertFalse((root / "build").exists())

    def test_documented_suite_stops_on_early_failure(self):
        readme = Path(__file__).with_name("README.md").read_text()
        recipe = readme.split("```sh\nfor case in ", 1)[1].split("```", 1)[0]
        result = subprocess.run(
            ("/usr/bin/bash", "-c", 'python3() { printf "%s\\n" "$5"; [[ $5 != missing-deny ]]; }\n'
             'for case in ' + recipe),
            text=True, capture_output=True, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.splitlines(), ["smoke", "missing-deny"])

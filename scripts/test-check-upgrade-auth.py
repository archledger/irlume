#!/usr/bin/env python3
"""Pure and refusal regressions: never run PAM, accounts, or guest checks."""
import contextlib
import importlib.util
import io
import json
import os
import stat
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "upgrade_auth", Path(__file__).with_name("check-upgrade-auth.py")
)
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)


class AuthCheckerTests(unittest.TestCase):
    def test_nonroot_refused_before_command_or_mutation(self):
        with patch.object(auth.os, "geteuid", return_value=1000), \
                patch.object(auth, "command") as command, \
                patch.object(auth, "run_stage") as run_stage:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(auth.main(["old-install"]), 1)
            self.assertEqual(json.loads(output.getvalue())["error"], "root-required")
            command.assert_not_called()
            run_stage.assert_not_called()

    def test_host_or_container_refused_before_marker_access(self):
        for kind in ("none", "docker", "lxc", "vmware", ""):
            with self.subTest(kind=kind), \
                    patch.object(auth.os, "geteuid", return_value=0), \
                    patch.object(auth, "command", return_value=(0, kind)), \
                    patch.object(auth.os, "open") as read:
                with self.assertRaisesRegex(auth.Failure, "qemu-kvm-required"):
                    auth.admit_guest()
                read.assert_not_called()

    def test_marker_must_be_exact_and_cannot_be_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "marker"
            with patch.object(auth, "MARKER", marker), \
                    patch.object(auth.os, "geteuid", return_value=0), \
                    patch.object(auth, "command", return_value=(0, "kvm")), \
                    patch.object(auth.os, "fstat", return_value=SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o644, st_uid=0)):
                for value in (b"", auth.MARKER_BYTES + b"\n", b"other"):
                    marker.write_bytes(value)
                    with self.assertRaisesRegex(auth.Failure, "marker-mismatch"):
                        auth.admit_guest()
                marker.write_bytes(auth.MARKER_BYTES)
                self.assertEqual(auth.admit_guest(), "kvm")
                marker.unlink()
                marker.symlink_to(Path(temp) / "other")
                with self.assertRaises(auth.Failure):
                    auth.admit_guest()

    def test_marker_owner_and_writable_modes_refuse_before_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "marker"
            marker.write_bytes(auth.MARKER_BYTES)
            for uid, mode in ((1000, 0o644), (0, 0o664), (0, 0o646), (0, 0o666)):
                with self.subTest(uid=uid, mode=oct(mode)), \
                        patch.object(auth, "MARKER", marker), \
                        patch.object(auth.os, "geteuid", return_value=0), \
                        patch.object(auth, "command", return_value=(0, "kvm")), \
                        patch.object(auth.os, "fstat", return_value=SimpleNamespace(
                            st_mode=stat.S_IFREG | mode, st_uid=uid)), \
                        patch.object(auth, "run_stage") as run_stage:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(auth.main(["old-install"]), 1)
                    self.assertEqual(json.loads(output.getvalue())["error"],
                                     "marker-owner-or-mode")
                    run_stage.assert_not_called()

    def test_invalid_stage_has_no_commands_or_mutations(self):
        with patch.object(auth, "command") as command, \
                patch.object(auth, "run_stage") as run_stage:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(auth.main(["wrong-stage"]), 1)
            self.assertEqual(json.loads(output.getvalue())["error"], "invalid-stage")
            command.assert_not_called()
            run_stage.assert_not_called()

    def test_sequencing_rejects_skips_and_repeated_first_stage(self):
        auth.check_stage("candidate-upgrade", "old-install")
        auth.check_stage("old-rollback", "candidate-upgrade")
        auth.check_stage("candidate-reupgrade", "old-rollback")
        for stage, previous in (("old-rollback", "old-install"),
                                ("old-install", "old-install"),
                                ("candidate-upgrade", None)):
            with self.assertRaisesRegex(auth.Failure, "stage-order"):
                auth.check_stage(stage, previous)

    def test_status_parser_checks_all_counters_and_cooldowns(self):
        text = (
            "Face retry state for 'irlume-upgrade-fixture': 2 recorded failures, 0s cooldown.\n"
            "Cumulative face requests: 7/50 consecutive unsuccessful; available after any cooldown.\n"
            "Password-verified retry reset: available for supported local accounts; 1 failed checks, 0s cooldown.\n"
            "Ordinary password login remains available.\n"
        )
        self.assertTrue(auth.check_status(text, 2, 7, 1))
        for changed in (text.replace("7/50", "0/50"),
                        text.replace("2 recorded", "0 recorded"),
                        text.replace("1 failed", "0 failed"),
                        text.replace("0s cooldown", "30s cooldown"),
                        text.replace("7/50", "7/500")):
            with self.assertRaisesRegex(auth.Failure, "retry-status-mismatch"):
                auth.check_status(changed, 2, 7, 1)
        self.assertFalse(auth.check_status(text.replace(
            "available for supported local accounts", "unavailable on this installation"), 2, 7, 1))

    def test_private_file_creation_never_overwrites_or_follows_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "private"
            auth.create_private(file, b"fixture")
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                auth.create_private(file, b"replacement")
            self.assertEqual(file.read_bytes(), b"fixture")
            alias = Path(temp) / "alias"
            alias.symlink_to(file)
            with self.assertRaises(FileExistsError):
                auth.create_private(alias, b"replacement")

    def test_command_uses_stdin_and_never_inherits_environment(self):
        secret = "synthetic-password-only"
        with patch.object(auth.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "discarded"
            auth.command(["pamtester", "service", "fixture", "authenticate"],
                         input_text=secret, capture=False)
            args, kwargs = run.call_args
            self.assertNotIn(secret, args[0])
            self.assertEqual(kwargs["input"], secret)
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["stdout"], auth.subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], auth.subprocess.DEVNULL)
            self.assertNotIn("LD_PRELOAD", kwargs["env"])
            self.assertLessEqual(kwargs["timeout"], 45)

    def test_packaged_module_discovers_all_distribution_layouts(self):
        cases = (
            ("dpkg-query", ["dpkg-query", "-L", "irlume"],
             "/usr/lib/x86_64-linux-gnu/security/pam_irlume.so"),
            ("pacman", ["pacman", "-Qlq", "irlume"],
             "/usr/lib/security/pam_irlume.so"),
            ("rpm", ["rpm", "-ql", "irlume"],
             "/usr/lib64/security/pam_irlume.so"),
        )
        for manager, query, module in cases:
            with self.subTest(manager=manager), \
                    patch.object(auth.shutil, "which", side_effect=(
                        lambda name, **kwargs: name if name == manager else None)), \
                    patch.object(auth, "command", return_value=(0, module + "\n")) as command, \
                    patch.object(Path, "is_file", return_value=True), \
                    patch.object(Path, "stat", return_value=SimpleNamespace(
                        st_size=1, st_uid=0, st_mode=stat.S_IFREG | 0o644)):
                self.assertEqual(auth.packaged_module(), Path(module))
                command.assert_called_once_with(query)

    def test_pam_wrong_password_requires_normal_rejection_exit(self):
        import signal
        for exit_code in (-signal.SIGSEGV, -signal.SIGKILL, 2, 126, 127, 255):
            with self.subTest(exit_code=exit_code), \
                    patch.object(auth, "command", side_effect=[(0, ""), (exit_code, "")]):
                with self.assertRaises(auth.Failure):
                    auth.pam_checks("synthetic-password-only")

    def test_pam_normal_success_and_rejection_are_reported(self):
        with patch.object(auth, "command", side_effect=[(0, ""), (1, "")]):
            self.assertEqual(auth.pam_checks("synthetic-password-only"),
                             {"correct_password_exit": 0, "wrong_password_exit": 1})

    def test_pam_wrong_password_success_is_rejected(self):
        with patch.object(auth, "command", side_effect=[(0, ""), (0, "")]):
            with self.assertRaises(auth.Failure):
                auth.pam_checks("synthetic-password-only")

    def test_credential_drop_uses_nss_supplementary_groups(self):
        from types import SimpleNamespace
        account = SimpleNamespace(pw_name="fixture", pw_uid=1234, pw_gid=1235)
        with patch.object(auth.os, "getgrouplist", return_value=[1235, 2345]) as groups, \
                patch.object(auth.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            auth.command(["irlume", "retry", "status"], account=account)
            groups.assert_called_once_with("fixture", 1235)
            self.assertEqual(run.call_args.kwargs["user"], 1234)
            self.assertEqual(run.call_args.kwargs["group"], 1235)
            self.assertEqual(run.call_args.kwargs["extra_groups"], [1235, 2345])

    def test_private_read_refuses_wide_modes_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "private"
            file.write_bytes(b"synthetic")
            os.chmod(file, 0o644)
            with self.assertRaisesRegex(auth.Failure, "private-file-metadata"):
                auth.read_private(file)
            alias = Path(temp) / "alias"
            alias.symlink_to(file)
            with self.assertRaises(OSError):
                auth.read_private(alias)

    def test_unexpected_error_never_emits_exception_payload(self):
        with patch.object(auth, "admit_guest", return_value="kvm"), \
                patch.object(auth, "run_stage", side_effect=ValueError("secret payload")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(auth.main(["old-install"]), 1)
            result = json.loads(output.getvalue())
            self.assertEqual(result["error"], "internal-check-failed")
            self.assertNotIn("secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()

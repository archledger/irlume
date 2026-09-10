#!/usr/bin/env python3
"""Local regressions for the disposable-guest harness; never install packages."""
import importlib.util
import io
import json
import os
import signal
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "package_upgrade", Path(__file__).with_name("test-package-upgrade.py")
)
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)


class HarnessTests(unittest.TestCase):
    def test_rpm_metadata_checks_upstream_name_epoch_and_architecture(self):
        good = "irlume\t(none)\t0.12.0\t1.20260910.fc44\tx86_64"
        with patch.object(upgrade, "read_command", return_value=good):
            self.assertEqual(upgrade.package_metadata(Path("/candidate.rpm"), "rpm", "0.12.0"),
                             "0.12.0-1.20260910.fc44")
        for bad in (good.replace("0.12.0", "0.12.01"), good.replace("(none)", "1"),
                    good.replace("x86_64", "aarch64"), good.replace("irlume\t", "other\t")):
            with patch.object(upgrade, "read_command", return_value=bad):
                with self.assertRaisesRegex(upgrade.Failure, "rpm-package-metadata"):
                    upgrade.package_metadata(Path("/candidate.rpm"), "rpm", "0.12.0")

    def test_rpm_transactions_move_matched_pair_in_each_direction(self):
        with tempfile.TemporaryFile() as log:
            runner = upgrade.Runner(log)
            for label, action in (("old-install", "install"), ("candidate-upgrade", "upgrade"),
                                  ("old-rollback", "downgrade"), ("candidate-reupgrade", "upgrade")):
                with patch.object(runner, "command") as command:
                    runner.install("rpm", Path("/main.rpm"), label, Path("/selinux.rpm"))
                    self.assertEqual(command.call_args.args[0],
                                     ["dnf5", "-y", "--setopt=localpkg_gpgcheck=True",
                                      action, "/main.rpm", "/selinux.rpm"])
                    self.assertEqual(command.call_args.kwargs, {"timeout": 900, "capture": False})

    def test_rpm_missing_or_mismatched_policy_pair_refused(self):
        with self.assertRaisesRegex(upgrade.Failure, "rpm-selinux-pair-required"):
            upgrade.rpm_companions(None, None, ("0.11.3-1.fc44", "0.12.0-1.fc44"))
        with patch.object(upgrade, "package_path", side_effect=[Path("/old.rpm"), Path("/new.rpm")]), \
             patch.object(upgrade, "package_metadata", side_effect=["0.11.3-1.fc44", "0.12.0-2.fc44"]):
            with self.assertRaisesRegex(upgrade.Failure, "rpm-main-policy-version-mismatch"):
                upgrade.rpm_companions("/old.rpm", "/new.rpm", ("0.11.3-1.fc44", "0.12.0-1.fc44"))

    def test_fedora_candidate_requires_lib64_pam_and_selinux_payload(self):
        paths = {
            "/usr/libexec/irlume-password-verify": 0o755,
            "/usr/libexec/irlume/irlume-kwallet-init": 0o755,
            "/usr/libexec/irlume/irlume-gkr-unlock": 0o755,
            "/etc/pam.d/irlume-retry-reset": 0o644,
            "/usr/share/polkit-1/actions/org.irlume.enroll.policy": 0o644,
            "/usr/share/polkit-1/actions/org.irlume.recovery-manage.policy": 0o644,
            "/usr/lib64/security/pam_irlume.so": 0o644,
            "/usr/share/selinux/packages/irlume.pp": 0o644,
        }
        payload = {path: {"type": "file", "mode": mode, "uid": 0, "gid": 0}
                   for path, mode in paths.items()}
        upgrade.check_candidate_payload(payload, "rpm")
        del payload["/usr/share/selinux/packages/irlume.pp"]
        with self.assertRaisesRegex(upgrade.Failure, "candidate-required-payload"):
            upgrade.check_candidate_payload(payload, "rpm")

    def test_rpm_selinux_check_refuses_permissive_or_missing_policy(self):
        with tempfile.TemporaryFile() as log:
            runner = upgrade.Runner(log)
            with patch.object(runner, "command", return_value="Permissive"):
                with self.assertRaisesRegex(upgrade.Failure, "selinux-not-enforcing"):
                    runner.selinux()
            for listing in ("base", "base\nirlume disabled"):
                with patch.object(runner, "command", side_effect=["Enforcing", listing]):
                    with self.assertRaisesRegex(upgrade.Failure, "selinux-module-not-enabled"):
                        runner.selinux()
            with patch.object(runner, "command", side_effect=["Enforcing", "base\nirlume"]):
                self.assertTrue(runner.selinux()["irlume_module_enabled"])

    def test_obsolete_conffile_requires_explicit_metadata_flag(self):
        md5 = "a" * 32
        output = f"/etc/regular {md5}\n /etc/obsolete {md5} obsolete\n"
        self.assertEqual(upgrade.obsolete_conffiles(output), {"/etc/obsolete"})
        with self.assertRaisesRegex(upgrade.Failure, "invalid-conffile-metadata"):
            upgrade.obsolete_conffiles("/etc/obsolete invalid-hash obsolete")

    def test_rollback_accepts_only_declared_obsolete_candidate_conffile(self):
        baseline = {"/usr/bin/irlume": {"sha256": "old"}}
        config = "/etc/pam.d/irlume-retry-reset"
        candidate = {"/usr/bin/irlume": {"sha256": "new"}, config: {"sha256": "config"}}
        residual = {config: candidate[config]}
        current = baseline | residual
        self.assertEqual(upgrade.check_rollback_payload(
            baseline, candidate, current, residual, {config}), residual)
        for obsolete in (set(), {"/etc/other"}):
            with self.assertRaisesRegex(upgrade.Failure, "candidate-payload-left"):
                upgrade.check_rollback_payload(baseline, candidate, current, residual, obsolete)
        with self.assertRaisesRegex(upgrade.Failure, "complete-old-payload"):
            upgrade.check_rollback_payload(baseline, candidate, candidate, residual, {config})
        binary = "/usr/bin/extra"
        with self.assertRaisesRegex(upgrade.Failure, "candidate-payload-left"):
            upgrade.check_rollback_payload(baseline, candidate | {binary: {}}, baseline | {binary: {}},
                                           {binary: {}}, {binary})

    def test_package_timeout_kills_surviving_group_after_leader_exits(self):
        with tempfile.TemporaryFile() as log, \
             patch.object(upgrade.subprocess, "Popen") as popen, \
             patch.object(upgrade.os, "killpg") as killpg, \
             patch.object(upgrade.time, "monotonic", side_effect=[0, 6]), \
             patch.object(upgrade.time, "sleep"):
            process = popen.return_value
            process.pid = 424242
            process.communicate.side_effect = [upgrade.subprocess.TimeoutExpired("fixture", 1),
                                               (None, None), (None, None)]
            with self.assertRaisesRegex(upgrade.Failure, "command-timeout"):
                upgrade.Runner(log).command(["fixture-only"], timeout=1, capture=False)
            self.assertIn(((424242, signal.SIGKILL), {}), killpg.call_args_list)

    def test_real_timeout_stops_term_ignoring_descendant(self):
        # Harmless Python processes only. The leader dies on TERM; its child
        # ignores TERM and has no inherited stdout pipe to keep communicate
        # waiting. This reproduces the package-log (capture=False) failure.
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryFile() as log:
            pid_file = Path(temp) / "child.pid"
            child = ("import os, signal, time\nfrom pathlib import Path\n"
                     "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                     f"Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
                     "while True: time.sleep(60)\n")
            leader = ("import subprocess, sys, time\n"
                      f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
                      "while True: time.sleep(60)\n")
            try:
                with self.assertRaisesRegex(upgrade.Failure, "command-timeout"):
                    upgrade.Runner(log).command([sys.executable, "-c", leader], timeout=1, capture=False)
                self.assertTrue(pid_file.is_file(), "child must start before timeout")
                pid = int(pid_file.read_text())
                state = Path(f"/proc/{pid}/stat")
                # The orphan may remain a zombie until the host's init reaps it.
                # Signal delivery is asynchronous even after killpg returns.
                deadline = time.monotonic() + 1
                while state.exists():
                    try:
                        status = state.read_text().split(")", 1)[1].split()[0]
                    except FileNotFoundError:
                        break
                    if status in {"Z", "X"}:
                        break
                    self.assertLess(time.monotonic(), deadline, "descendant survived SIGKILL")
                    time.sleep(0.01)
            finally:
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_unsafe_main_creates_no_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result.json"
            with patch.object(upgrade.os, "geteuid", return_value=1000), \
                 patch.object(upgrade.subprocess, "Popen") as command, \
                 patch.object(upgrade.sys, "stderr", io.StringIO()):
                self.assertEqual(upgrade.main(["--old", "/bad.deb", "--candidate", "/new.deb",
                                               "--output", str(output)]), 2)
                command.assert_not_called()
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_non_root_refused_before_commands(self):
        with patch.object(upgrade.os, "geteuid", return_value=1000), \
             patch.object(upgrade, "read_command") as command:
            with self.assertRaisesRegex(upgrade.Failure, "root-required"):
                upgrade.admit_guest()
            command.assert_not_called()

    def test_host_and_container_refused_before_marker_read(self):
        for kind in ("none", "docker", "lxc", "vmware", ""):
            with self.subTest(kind=kind), \
                 patch.object(upgrade.os, "geteuid", return_value=0), \
                 patch.object(upgrade, "read_command", return_value=kind) as command, \
                 patch.object(Path, "read_bytes") as read:
                with self.assertRaisesRegex(upgrade.Failure, "qemu-kvm-required"):
                    upgrade.admit_guest()
                read.assert_not_called()
                command.assert_called_once_with(["systemd-detect-virt"])

    def test_container_inside_qemu_refused_before_marker_or_mutation(self):
        # --vm hides this container and reports the outer QEMU machine.
        def detect(argv):
            return "qemu" if "--vm" in argv else "docker"

        with tempfile.TemporaryDirectory() as temp, \
             patch.object(upgrade.os, "geteuid", return_value=0), \
             patch.object(upgrade, "read_command", side_effect=detect) as command, \
             patch.object(upgrade, "no_symlinks") as marker_check, \
             patch.object(upgrade, "execute") as execute, \
             patch.object(upgrade.sys, "stderr", io.StringIO()) as stderr:
            output = Path(temp) / "result.json"
            self.assertEqual(upgrade.main(["--old", "/old.deb", "--candidate", "/candidate.deb",
                                           "--output", str(output)]), 2)
            self.assertIn("qemu-kvm-required", stderr.getvalue())
            command.assert_called_once_with(["systemd-detect-virt"])
            marker_check.assert_not_called()
            execute.assert_not_called()
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_marker_is_exact_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "marker"
            real_stat = Path.stat

            def root_marker_stat(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if path == marker:
                    fields = list(result)
                    fields[4] = 0
                    return os.stat_result(fields)
                return result

            with patch.object(upgrade, "MARKER", marker), \
                 patch.object(upgrade.os, "geteuid", return_value=0), \
                 patch.object(Path, "stat", autospec=True, side_effect=root_marker_stat), \
                 patch.object(upgrade, "read_command", return_value="kvm"):
                for content in (b"", upgrade.MARKER_BYTES + b"\n"):
                    marker.write_bytes(content)
                    with self.assertRaisesRegex(upgrade.Failure, "marker-mismatch"):
                        upgrade.admit_guest()
                marker.write_bytes(upgrade.MARKER_BYTES)
                self.assertEqual(upgrade.admit_guest(), "kvm")
                target = Path(temp) / "target"
                marker.rename(target)
                marker.symlink_to(target)
                with self.assertRaisesRegex(upgrade.Failure, "symlink"):
                    upgrade.admit_guest()

    def test_input_path_rejects_escape_and_symlink_ancestor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "input"
            root.mkdir()
            package = root / "old.deb"
            package.write_bytes(b"fixture")
            with patch.object(upgrade, "INPUT_ROOT", root):
                self.assertEqual(upgrade.package_path(str(package)), package)
                with self.assertRaisesRegex(upgrade.Failure, "input-location"):
                    upgrade.package_path(str(Path(temp) / "outside.deb"))
                (root / "alias").symlink_to(root, target_is_directory=True)
                with self.assertRaisesRegex(upgrade.Failure, "symlink"):
                    upgrade.package_path(str(root / "alias/old.deb"))

    def test_wrong_package_version_and_name_refused(self):
        for fields in (("irlume", "0.11.30"), ("other", "0.11.3")):
            with patch.object(upgrade, "read_command", side_effect=fields):
                with self.assertRaisesRegex(upgrade.Failure, "package-metadata"):
                    upgrade.package_metadata(Path("/old.deb"), "deb", "0.11.3")

    def test_arch_release_suffix_is_not_cli_version(self):
        with patch.object(upgrade, "read_command", return_value=(
            "pkgname = irlume\npkgver = 0.11.3-2\n")):
            self.assertEqual(upgrade.package_metadata(
                Path("/old.pkg.tar.zst"), "arch", "0.11.3"), "0.11.3-2")

    def test_preservation_detects_contents_modes_and_tree_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / "synthetic"
            child.write_bytes(b"synthetic only")
            os.chmod(child, 0o600)
            before = upgrade.snapshot_tree(root)
            child.write_bytes(b"changed")
            self.assertNotEqual(before, upgrade.snapshot_tree(root))
            child.write_bytes(b"synthetic only")
            os.chmod(child, 0o644)
            self.assertNotEqual(before, upgrade.snapshot_tree(root))
            os.chmod(child, 0o600)
            (root / "unexpected").mkdir()
            self.assertNotEqual(before, upgrade.snapshot_tree(root))

    def test_root_mode_tightening_is_allowed_but_widening_fails(self):
        upgrade.check_root_state({"mode": 0o755, "uid": 0, "gid": 0},
                                 {"mode": 0o700, "uid": 0, "gid": 0})
        with self.assertRaisesRegex(upgrade.Failure, "state-root-permissions"):
            upgrade.check_root_state({"mode": 0o700, "uid": 0, "gid": 0},
                                     {"mode": 0o755, "uid": 0, "gid": 0})

    def test_live_daemon_must_restart_and_match_installed_executable(self):
        with self.assertRaisesRegex(upgrade.Failure, "daemon-not-restarted"):
            upgrade.check_daemon_identity(42, "abc", "abc", 42)
        with self.assertRaisesRegex(upgrade.Failure, "daemon-executable-mismatch"):
            upgrade.check_daemon_identity(43, "old", "new", 42)
        upgrade.check_daemon_identity(43, "new", "new", 42)

    def test_cli_version_match_is_exact(self):
        for text in ("irlume 0.11.30", "irlume 0.12.0", ""):
            with self.assertRaisesRegex(upgrade.Failure, "cli-version-mismatch"):
                upgrade.check_cli_version(text, "0.11.3")
        upgrade.check_cli_version("irlume 0.11.3\n", "0.11.3")

    def test_stage_checker_nonzero_or_non_json_fails(self):
        with tempfile.TemporaryFile() as log:
            runner = upgrade.Runner(log)
            with patch.object(upgrade.subprocess, "Popen") as popen:
                popen.return_value.communicate.return_value = (b'{"passed":false}', None)
                popen.return_value.returncode = 1
                with self.assertRaisesRegex(upgrade.Failure, "command-failed"):
                    runner.stage_check(Path("/checker.py"), "old-install")
                popen.return_value.returncode = 0
                for output in (b"not JSON", b"[]", b'{"passed":false}'):
                    popen.return_value.communicate.return_value = (output, None)
                    with self.assertRaises(upgrade.Failure):
                        runner.stage_check(Path("/checker.py"), "old-install")

    def test_failed_package_transaction_persists_failure_without_raw_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old, candidate = root / "old.deb", root / "candidate.deb"
            old.write_bytes(b"old synthetic package")
            candidate.write_bytes(b"candidate synthetic package")
            output = root / "result.json"
            processes = []
            for data in (b"", b"PRIVATE GUEST DIAGNOSTIC", b"", b""):
                process = Mock(returncode=1)
                process.communicate.return_value = (data, None)
                processes.append(process)
            with patch.object(upgrade, "INPUT_ROOT", root), \
                 patch.object(upgrade, "admit_guest", return_value="kvm"), \
                 patch.object(upgrade, "read_command", side_effect=["irlume", "0.11.3", "irlume", "0.12.0"]), \
                 patch.object(upgrade.subprocess, "Popen", side_effect=processes) as command, \
                 patch.object(upgrade.sys, "stdout", io.StringIO()):
                self.assertEqual(upgrade.main(["--old", str(old), "--candidate", str(candidate),
                                               "--output", str(output)]), 1)
            receipt = json.loads(output.read_text())
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["steps"], [{"step": "old-install", "passed": False}])
            self.assertEqual(receipt["failure"], "command-failed")
            self.assertNotIn("PRIVATE GUEST DIAGNOSTIC", output.read_text())
            self.assertIn("PRIVATE GUEST DIAGNOSTIC", output.with_name(output.name + ".log").read_text())
            self.assertEqual(command.call_args_list[1].args[0][0], "apt-get")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Source-contract tests for the slice-4 hardware runner's unit guard."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


DEFAULT_RUNNER = Path(__file__).with_name("run-slice4-hardware.sh")
RUNNER = Path(os.environ.get("IRLUME_RUNNER_UNDER_TEST", DEFAULT_RUNNER))
SUPPORT = Path(__file__).with_name("slice4-runner-support.py")


class RunnerUnitGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = RUNNER.read_text(encoding="utf-8")

    def test_socket_activation_is_quiesced_before_the_service_and_ownership_probe(self):
        socket_stop = self.source.index(
            'if ! unit_is_quiescent irlumed.socket; then\n'
            '    sudo -n systemctl stop irlumed.socket'
        )
        service_stop = self.source.index(
            'if ! unit_is_quiescent irlumed.service; then\n'
            '    sudo -n systemctl stop irlumed.service'
        )
        ownership_probe = self.source.index('sudo -n fuser "${nodes[@]}"')
        self.assertLess(socket_stop, service_stop)
        self.assertLess(service_stop, ownership_probe)

    def test_restore_order_cannot_socket_activate_a_not_yet_restored_service(self):
        restore_start = self.source.index("restore_units() {")
        cleanup_start = self.source.index("cleanup() {")
        restore = self.source[restore_start:cleanup_start]
        first_service = restore.index(
            'restore_one_unit irlumed.service "$service_was_active"'
        )
        socket_restore = restore.index(
            'restore_one_unit irlumed.socket "$socket_was_active"'
        )
        second_service = restore.rindex(
            'restore_one_unit irlumed.service "$service_was_active"'
        )
        self.assertLess(first_service, socket_restore)
        self.assertLess(socket_restore, second_service)

    def test_cleanup_and_success_paths_both_restore_the_observed_unit_state(self):
        self.assertEqual(self.source.count("restore_units"), 2)
        self.assertIn('trap cleanup EXIT', self.source)
        self.assertIn(
            'if ! unit_is_quiescent irlumed.socket '
            '|| ! unit_is_quiescent irlumed.service; then',
            self.source,
        )

    def test_transitional_systemd_states_never_count_as_quiescent(self):
        self.assertNotIn("systemctl is-active --quiet irlumed", self.source)
        self.assertIn("unit_active_state() {", self.source)
        quiescent_start = self.source.index("unit_is_quiescent() {")
        restored_start = self.source.index("require_restored_state() {")
        quiescent = self.source[quiescent_start:restored_start]
        self.assertIn("inactive | failed)", quiescent)
        for transitional in (
            "activating",
            "deactivating",
            "reloading",
            "refreshing",
        ):
            self.assertNotIn(transitional, quiescent)
        self.assertIn("if ! unit_is_quiescent irlumed.socket; then", self.source)
        self.assertIn("if ! unit_is_quiescent irlumed.service; then", self.source)
        self.assertIn(
            'restore_one_unit irlumed.service "$service_was_active"',
            self.source,
        )
        self.assertIn(
            'restore_one_unit irlumed.socket "$socket_was_active"',
            self.source,
        )

    def test_initial_transitional_states_are_refused_not_snapshotted_as_active(self):
        snapshot_start = self.source.index("snapshot_unit_active() {")
        quiescent_start = self.source.index("unit_is_quiescent() {")
        snapshot = self.source[snapshot_start:quiescent_start]
        self.assertIn('case "$state" in\n        active)', snapshot)
        active_branch = snapshot.split("inactive | failed)", 1)[0]
        for transitional in (
            "activating",
            "deactivating",
            "reloading",
            "refreshing",
        ):
            self.assertNotIn(transitional, active_branch)

    def test_restoration_actively_requiesces_units_and_defers_pass_to_cleanup(self):
        restore_start = self.source.index("restore_one_unit() {")
        restore_units_start = self.source.index("restore_units() {")
        restore_one = self.source[restore_start:restore_units_start]
        self.assertIn(
            'if [ "$expected_active" -eq 0 ] && ! unit_is_quiescent "$unit"; then',
            restore_one,
        )
        self.assertIn('sudo -n systemctl stop "$unit" || return 1', restore_one)
        self.assertIn('sudo -n systemctl start "$unit" || return 1', restore_one)
        self.assertIn(
            'require_restored_state "$unit" "$expected_active" || return 1',
            restore_one,
        )

        restore_units = self.source[restore_units_start:self.source.index("cleanup() {")]
        self.assertEqual(restore_units.count("restore_one_unit"), 3)
        self.assertEqual(restore_units.count("|| return 1"), 3)
        self.assertGreater(
            restore_units.index("units_restored=1"),
            restore_units.rindex("restore_one_unit"),
        )

        cleanup_start = self.source.index("cleanup() {")
        signal_start = self.source.index("on_signal() {")
        cleanup = self.source[cleanup_start:signal_start]
        self.assertIn(
            'if [ "$status" -ne 0 ] && [ "$evidence_published" -eq 1 ]; then',
            cleanup,
        )
        self.assertIn('rm -f -- "$evidence"', cleanup)
        self.assertIn("hardware-run: PASS", cleanup)
        self.assertIn(
            'if [ "$status" -eq 0 ] && [ "$evidence_published" -eq 1 ]; then',
            cleanup,
        )
        self.assertEqual(self.source.count("hardware-run: PASS"), 1)
        published = self.source.index("evidence_published=1")
        durable = self.source.index(
            '"$script_dir/slice4-runner-support.py" durable-evidence'
        )
        self.assertLess(published, durable)
        self.assertIn(
            '"$evidence" "$run_dir" "$output_dir" "$source_worktree"',
            self.source[durable:],
        )

    def test_runs_are_host_serialized_and_publish_to_unique_invocation_paths(self):
        lock = self.source.index('"$script_dir/slice4-runner-support.py" hold-lock')
        snapshot = self.source.index(
            "service_was_active=$(snapshot_unit_active irlumed.service)"
        )
        self.assertLess(lock, snapshot)
        self.assertIn('runtime_dir="/run/user/$(id -u)"', self.source)
        self.assertNotIn("XDG_RUNTIME_DIR", self.source)
        self.assertIn('[ "$(realpath "$runtime_dir")" != "$runtime_dir" ]', self.source)
        self.assertIn('[ "$(stat -c %a "$runtime_dir")" != 700 ]', self.source)
        self.assertIn('lock_dir="$runtime_dir/irlume-slice4-hardware.lock"', self.source)
        self.assertIn('exec env IRLUME_SLICE4_LOCK_HELD=1 python3', self.source)
        self.assertIn('unset IRLUME_SLICE4_LOCK_HELD', self.source)
        self.assertNotIn('exec {lock_fd}', self.source)
        self.assertIn(
            'run_dir=$(mktemp -d "$output_dir/slice4-${host}-${sha}.XXXXXX")',
            self.source,
        )
        self.assertIn('log="$run_dir/run.log"', self.source)
        self.assertIn('evidence="$run_dir/evidence.json"', self.source)
        self.assertNotIn('slice4-hardware-${host}-${sha}.json', self.source)
        self.assertIn('[ -L "$output_dir" ]', self.source)
        self.assertIn('[ "$(realpath "$output_dir")" != "$output_dir" ]', self.source)

    def test_lock_holder_does_not_leak_lock_fd_to_workload_descendants(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock_dir = root / "lock"
            lock_dir.mkdir()
            ready = root / "ready"
            child = textwrap.dedent(
                """
                import os
                from pathlib import Path
                import sys
                import time

                lock = Path(sys.argv[1]).resolve()
                targets = []
                for entry in Path("/proc/self/fd").iterdir():
                    try:
                        targets.append(Path(os.readlink(entry)).resolve())
                    except FileNotFoundError:
                        pass
                assert lock not in targets, targets
                Path(sys.argv[2]).write_text("ready", encoding="utf-8")
                time.sleep(1)
                """
            )
            holder = subprocess.Popen(
                [
                    sys.executable,
                    str(SUPPORT),
                    "hold-lock",
                    str(lock_dir),
                    sys.executable,
                    "-c",
                    child,
                    str(lock_dir),
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and holder.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("lock-holder child did not become ready")
                    time.sleep(0.01)
                self.assertIsNone(holder.poll())
                blocked = subprocess.run(
                    [
                        sys.executable,
                        str(SUPPORT),
                        "hold-lock",
                        str(lock_dir),
                        sys.executable,
                        "-c",
                        "pass",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(blocked.returncode, 75, blocked)
                self.assertIn("another slice-4 hardware run", blocked.stderr)
            finally:
                stdout, stderr = holder.communicate(timeout=5)
            self.assertEqual(holder.returncode, 0, (stdout, stderr))
            reacquired = subprocess.run(
                [
                    sys.executable,
                    str(SUPPORT),
                    "hold-lock",
                    str(lock_dir),
                    sys.executable,
                    "-c",
                    "pass",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(reacquired.returncode, 0, reacquired)

    def test_durable_evidence_fsyncs_file_and_every_establishing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source"
            output = source / "target"
            run_dir = output / "run"
            run_dir.mkdir(parents=True)
            evidence = run_dir / "evidence.json"
            evidence.write_text("{}\n", encoding="utf-8")
            trace = Path(tmp) / "fsync.trace"
            shim_source = Path(tmp) / "fsync-shim.c"
            shim = Path(tmp) / "fsync-shim.so"
            shim_source.write_text(
                textwrap.dedent(
                    r"""
                    #define _GNU_SOURCE
                    #include <errno.h>
                    #include <fcntl.h>
                    #include <limits.h>
                    #include <stdio.h>
                    #include <stdlib.h>
                    #include <string.h>
                    #include <sys/syscall.h>
                    #include <unistd.h>

                    int fsync(int fd) {
                        char link[64], target[PATH_MAX], line[PATH_MAX + 2];
                        const char *trace = getenv("IRLUME_FSYNC_TRACE");
                        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
                        ssize_t length = readlink(link, target, sizeof(target) - 1);
                        if (length >= 0 && trace) {
                            target[length] = '\0';
                            int out = open(trace, O_WRONLY | O_CREAT | O_APPEND, 0600);
                            if (out >= 0) {
                                int bytes = snprintf(line, sizeof(line), "%s\n", target);
                                (void)write(out, line, (size_t)bytes);
                                close(out);
                            }
                        }
                        if (getenv("IRLUME_FSYNC_FAIL")) {
                            errno = EIO;
                            return -1;
                        }
                        return (int)syscall(SYS_fsync, fd);
                    }
                    """
                ),
                encoding="utf-8",
            )
            subprocess.run(
                ["cc", "-shared", "-fPIC", "-o", str(shim), str(shim_source)],
                check=True,
                capture_output=True,
                text=True,
            )
            command = [
                sys.executable,
                str(SUPPORT),
                "durable-evidence",
                str(evidence),
                str(run_dir),
                str(output),
                str(source),
            ]
            env = os.environ | {
                "LD_PRELOAD": str(shim),
                "IRLUME_FSYNC_TRACE": str(trace),
            }
            durable = subprocess.run(
                command, env=env, capture_output=True, text=True, check=False
            )
            self.assertEqual(durable.returncode, 0, durable)
            self.assertEqual(
                trace.read_text(encoding="utf-8").splitlines(),
                [str(evidence), str(run_dir), str(output), str(source)],
            )

            failed = subprocess.run(
                command,
                env=env | {"IRLUME_FSYNC_FAIL": "1"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(failed.returncode, 0, failed)
            self.assertIn("Input/output error", failed.stderr)

    def test_cleanup_errors_are_accumulated_before_failed_evidence_is_purged(self):
        cleanup_start = self.source.index("cleanup() {")
        signal_start = self.source.index("on_signal() {")
        cleanup = self.source[cleanup_start:signal_start]
        self.assertIn('if ! rm -f "$users_file" "$fuser_errors"; then', cleanup)
        self.assertIn('if ! rm -rf "$snapshot_parent" "$build_dir"; then', cleanup)
        purge = cleanup.index('rm -f -- "$evidence"')
        temp_cleanup = cleanup.index('rm -rf "$snapshot_parent" "$build_dir"')
        self.assertGreater(purge, temp_cleanup)

if __name__ == "__main__":
    unittest.main()

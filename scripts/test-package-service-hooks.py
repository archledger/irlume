#!/usr/bin/env python3
"""Execute package hooks with isolated command shims; never change host services.

Requires dpkg and vercmp so migration decisions use the native comparators.
The shell executes a copy with only /var/lib/irlume relocated into the fixture
to isolate the unrelated reconcile marker; service commands and branches are
unchanged. All external commands use a private PATH.
These tests cover hook decisions, not systemd's dependency/activation engine.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DAEMON = "irlumed.service"
SOCKET = "irlumed.socket"

# Model the systemctl command boundary, including enable vs. --now and masks.
# Unsupported commands are recorded as errors even when a hook ignores status.
SHIM = r'''
import json
import os
from pathlib import Path
import sys

path = Path(os.environ["HOOK_STATE"])
state = json.loads(path.read_text())
name = Path(sys.argv[0]).name
args = sys.argv[1:]
state["calls"].append([name, *args])
status = 0

def unexpected():
    state["errors"].append([name, *args])
    return 99

if name == "systemctl":
    verb = args[0] if args else ""
    flags = [arg for arg in args[1:] if arg.startswith("-")]
    units = [arg for arg in args[1:] if not arg.startswith("-")]
    if verb == "daemon-reload" and not flags and not units:
        pass
    elif verb in {"is-enabled", "is-active"} and flags == ["--quiet"] and len(units) == 1:
        unit = state["units"].get(units[0])
        if unit is None:
            status = unexpected()
        elif verb == "is-enabled":
            status = 0 if unit["enabled"] in {"enabled", "enabled-runtime"} else 1
        else:
            status = 0 if unit["active"] else 3
    elif verb in {"enable", "start", "try-restart"} and units and (
        not flags or (verb == "enable" and flags == ["--now"])
    ):
        for unit_name in units:
            if unit_name.startswith("irlume-reconcile."):
                continue
            unit = state["units"].get(unit_name)
            if unit is None:
                status = unexpected()
                continue
            if unit["enabled"] in {"masked", "masked-runtime"}:
                status = 1
                continue
            if verb == "enable":
                unit["enabled"] = "enabled"
            if verb == "start" or (verb == "enable" and "--now" in flags):
                if not unit["active"]:
                    unit["starts"] += 1
                unit["active"] = True
            if verb == "try-restart" and unit["active"]:
                unit["restarts"] += 1
    else:
        status = unexpected()
elif name == "systemd-tmpfiles" and args == ["--create", "irlume.conf"]:
    pass
elif name == "apparmor_parser" and args == ["-r", "/etc/apparmor.d/usr.bin.irlumed"]:
    pass
else:
    status = unexpected()

path.write_text(json.dumps(state))
sys.exit(status)
'''

class PackageServiceHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.commands = {}
        for name in ("dpkg", "vercmp", "cat", "bash", "sh"):
            executable = shutil.which(name)
            if executable is None:
                raise RuntimeError(f"required test dependency missing: {name}")
            cls.commands[name] = executable

    def run_hook(self, family, service, socket, old="0.11.3"):
        with tempfile.TemporaryDirectory(prefix="irlume-hook-test-") as temp:
            directory = Path(temp)
            # A real marker under a private path works with both dash and Bash.
            # Do not override shell builtins: dash rejects a function named [.
            fixture_state = directory / "var/lib/irlume"
            fixture_state.mkdir(parents=True)
            (fixture_state / ".reconcile-timer-armed").touch()
            source = ROOT / ("packaging/debian/postinstall.sh" if family == "debian"
                             else "packaging/arch/irlume.install")
            hook = directory / "hook.sh"
            hook.write_text(source.read_text().replace("/var/lib/irlume", str(fixture_state)))
            state_path = directory / "state.json"
            state_path.write_text(json.dumps({
                "units": {
                    DAEMON: {"enabled": service[0], "active": service[1], "starts": 0, "restarts": 0},
                    SOCKET: {"enabled": socket[0], "active": socket[1], "starts": 0, "restarts": 0},
                },
                "calls": [], "errors": [],
            }))
            for name in ("systemctl", "systemd-tmpfiles", "apparmor_parser", "mkdir"):
                shim = directory / name
                shim.write_text(f"#!{sys.executable}\n{SHIM}")
                shim.chmod(0o700)
            for name in ("dpkg", "vercmp", "cat"):
                (directory / name).symlink_to(self.commands[name])
            env = {
                "PATH": str(directory), "HOOK_STATE": str(state_path),
                "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
            }
            if family == "debian":
                command = [self.commands["sh"], str(hook), "configure"]
                if old is not None:
                    command.append(old)
            else:
                env["HOOK_SCRIPT"] = str(hook)
                function = "post_install" if old is None else "post_upgrade"
                # Bash can read .bashrc for noninteractive remote invocations,
                # even with a clean environment. Never run the user's startup.
                command = [self.commands["bash"], "--noprofile", "--norc", "-c",
                           f'. "$HOOK_SCRIPT"\n{function} "$@"\n',
                           "hook-test", "0.12.0-1"]
                if old is not None:
                    command.append(old)
            with subprocess.Popen(command, env=env, cwd=directory, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, start_new_session=True) as process:
                try:
                    stdout, stderr = process.communicate(timeout=10)
                except BaseException:
                    # A timeout/interrupt must not leave a shell child behind.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.communicate()
                    raise
            state = json.loads(state_path.read_text())
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stderr, "", stdout)
            self.assertEqual(state["errors"], [], "unexpected or unsafe hook command")
            return state

    def assert_unit(self, state, unit, enabled, active, starts=0, restarts=0):
        self.assertEqual(state["units"][unit], {
            "enabled": enabled, "active": active, "starts": starts, "restarts": restarts,
        }, state["calls"])

    def test_modern_upgrade_preserves_enabled_stopped_units(self):
        for family in ("debian", "arch"):
            with self.subTest(family=family):
                state = self.run_hook(family, ("enabled", False), ("enabled", False))
                self.assert_unit(state, DAEMON, "enabled", False)
                self.assert_unit(state, SOCKET, "enabled", False)

    def test_modern_upgrade_preserves_independently_disabled_socket(self):
        for family in ("debian", "arch"):
            with self.subTest(family=family):
                state = self.run_hook(family, ("enabled", False), ("disabled", False))
                self.assert_unit(state, DAEMON, "enabled", False)
                self.assert_unit(state, SOCKET, "disabled", False)

    def test_modern_upgrade_restarts_active_daemon_without_reenabling_units(self):
        for family in ("debian", "arch"):
            for enabled in ("enabled", "disabled", "enabled-runtime"):
                with self.subTest(family=family, enabled=enabled):
                    state = self.run_hook(family, (enabled, True), (enabled, True))
                    self.assert_unit(state, DAEMON, enabled, True, restarts=1)
                    self.assert_unit(state, SOCKET, enabled, True)

    def test_modern_upgrade_keeps_disabled_stopped_units_stopped(self):
        for family in ("debian", "arch"):
            with self.subTest(family=family):
                state = self.run_hook(family, ("disabled", False), ("disabled", False))
                self.assert_unit(state, DAEMON, "disabled", False)
                self.assert_unit(state, SOCKET, "disabled", False)

    def test_upgrade_respects_service_and_socket_masks(self):
        for family in ("debian", "arch"):
            for old in ("0.8.0", "0.11.3"):
                for mask in ("masked", "masked-runtime"):
                    for service in ("enabled", mask):
                        with self.subTest(family=family, old=old, mask=mask, service=service):
                            state = self.run_hook(family, (service, False), (mask, False), old)
                            self.assert_unit(state, DAEMON, service, False)
                            self.assert_unit(state, SOCKET, mask, False)

    def test_first_install_enables_and_starts_both_units(self):
        for family in ("debian", "arch"):
            with self.subTest(family=family):
                state = self.run_hook(family, ("disabled", False), ("disabled", False), None)
                self.assert_unit(state, DAEMON, "enabled", True, starts=1,
                                 restarts=1 if family == "debian" else 0)
                self.assert_unit(state, SOCKET, "enabled", True, starts=1)

    def test_pre_socket_upgrade_enables_but_does_not_start_for_stopped_service(self):
        for family in ("debian", "arch"):
            for old in ("0.7.0", "0.8.0", "0.8.0-2"):
                with self.subTest(family=family, old=old):
                    state = self.run_hook(family, ("enabled", False), ("disabled", False), old)
                    self.assert_unit(state, DAEMON, "enabled", False)
                    self.assert_unit(state, SOCKET, "enabled", False)

    def test_pre_socket_upgrade_starts_socket_for_enabled_running_service(self):
        for family in ("debian", "arch"):
            with self.subTest(family=family):
                state = self.run_hook(family, ("enabled", True), ("disabled", False), "0.8.0-1")
                self.assert_unit(state, DAEMON, "enabled", True, restarts=1)
                self.assert_unit(state, SOCKET, "enabled", True, starts=1)

    def test_pre_socket_upgrade_keeps_disabled_service_and_socket_disabled(self):
        for family in ("debian", "arch"):
            for active in (False, True):
                with self.subTest(family=family, active=active):
                    state = self.run_hook(family, ("disabled", active), ("disabled", False), "0.8.0")
                    self.assert_unit(state, DAEMON, "disabled", active, restarts=int(active))
                    self.assert_unit(state, SOCKET, "disabled", False)

    def test_socket_release_and_later_package_versions_do_not_migrate(self):
        # pkgrel is part of pacman's old-version argument; Debian versions can
        # carry revisions and prereleases. Native comparison avoids lexical
        # mistakes (0.11.3 sorts before 0.8.1 as text).
        for family, versions in (
            ("debian", ("0.8.1", "0.8.1-2", "0.8.1+git1", "0.12.0~rc1-1", "0.12.0-1")),
            ("arch", ("0.8.1-1", "0.8.1-2", "0.8.1.r1-1", "0.12.0rc1-1", "0.12.0-1")),
        ):
            for old in versions:
                with self.subTest(family=family, old=old):
                    state = self.run_hook(family, ("enabled", False), ("disabled", False), old)
                    self.assert_unit(state, SOCKET, "disabled", False)


if __name__ == "__main__":
    unittest.main()

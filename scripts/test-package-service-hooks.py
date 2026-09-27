#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Execute package hooks with isolated command shims; never change host services.

Requires dpkg and vercmp so migration decisions use the native comparators.
The shell executes a copy with only /var/lib/irlume relocated into the fixture
to isolate the reconcile timer marker; service commands and branches are
unchanged. Fedora's %post is taken from the spec with its one macro,
%systemd_post, replaced by the preset call it makes on a first install.
All external commands use a private PATH.
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
RECONCILE = ("irlume-reconcile.path", "irlume-reconcile.timer", "irlume-reconcile.service")
FEDORA_PRESET = [line.split()[1] for line in
                 (ROOT / "packaging/fedora/90-irlume.preset").read_text().splitlines()
                 if line.startswith("enable ")]

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
    elif args[:2] == ["--no-reload", "preset"] and len(args) > 2:
        # What %systemd_post runs on a first install; a mask stays.
        for unit_name in args[2:]:
            unit = state["units"].get(unit_name)
            if unit is None:
                status = unexpected()
            elif unit["enabled"] in {"masked", "masked-runtime"}:
                status = 1
            else:
                unit["enabled"] = "enabled" if unit_name in state["preset"] else "disabled"
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
elif name == "mkdir" and args == ["-p", "-m", "0700", os.environ["HOOK_STATE_DIR"]]:
    Path(args[3]).mkdir(mode=0o700, parents=True, exist_ok=True)
elif name == "touch" and args == [os.environ["HOOK_STATE_DIR"] + "/.reconcile-timer-armed"]:
    Path(args[0]).touch()
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

    @staticmethod
    def fedora_post():
        # The main package's %post, with %systemd_post replaced by what it
        # expands to (systemd's macros.systemd: on a first install,
        # systemd-update-helper runs `systemctl --no-reload preset` on the
        # units) and %% by the % it stands for.
        spec = (ROOT / "packaging/fedora/irlume.spec").read_text()
        body = spec.split("\n%post\n", 1)[1].split("\n%preun\n", 1)[0]
        lines = []
        for line in body.splitlines():
            if line.startswith("%systemd_post "):
                units = line.split(None, 1)[1]
                line = f"if [ $1 -eq 1 ]; then systemctl --no-reload preset {units} || :; fi"
            elif "%" in line and not line.lstrip().startswith("#"):
                raise AssertionError(f"no model for the macro in this %post line: {line}")
            lines.append(line.replace("%%", "%"))
        return "\n".join(lines) + "\n"

    def run_hook(self, family, service, socket, old="0.11.3", reconcile=("enabled", False),
                 timer_armed=True):
        # reconcile is one (enabled, active) pair for all three units, or a
        # dict giving each unit its own. timer_armed=False leaves out the
        # one-time timer marker, as on an install from before 0.7.0 or an
        # Arch install that has not been upgraded since.
        if isinstance(reconcile, tuple):
            reconcile = dict.fromkeys(RECONCILE, reconcile)
        with tempfile.TemporaryDirectory(prefix="irlume-hook-test-") as temp:
            directory = Path(temp)
            # A real marker under a private path works with both dash and Bash.
            # Do not override shell builtins: dash rejects a function named [.
            fixture_state = directory / "var/lib/irlume"
            fixture_state.mkdir(parents=True)
            marker = fixture_state / ".reconcile-timer-armed"
            if timer_armed:
                marker.touch()
            if family == "fedora":
                text = self.fedora_post()
            else:
                text = (ROOT / ("packaging/debian/postinstall.sh" if family == "debian"
                                else "packaging/arch/irlume.install")).read_text()
            hook = directory / "hook.sh"
            hook.write_text(text.replace("/var/lib/irlume", str(fixture_state)))
            state_path = directory / "state.json"
            state_path.write_text(json.dumps({
                "units": {
                    DAEMON: {"enabled": service[0], "active": service[1], "starts": 0, "restarts": 0},
                    SOCKET: {"enabled": socket[0], "active": socket[1], "starts": 0, "restarts": 0},
                    **{unit: {"enabled": reconcile[unit][0], "active": reconcile[unit][1],
                              "starts": 0, "restarts": 0} for unit in RECONCILE},
                },
                "preset": FEDORA_PRESET, "calls": [], "errors": [],
            }))
            for name in ("systemctl", "systemd-tmpfiles", "apparmor_parser", "mkdir", "touch"):
                shim = directory / name
                shim.write_text(f"#!{sys.executable}\n{SHIM}")
                shim.chmod(0o700)
            for name in ("dpkg", "vercmp", "cat"):
                (directory / name).symlink_to(self.commands[name])
            env = {
                "PATH": str(directory), "HOOK_STATE": str(state_path),
                "HOOK_STATE_DIR": str(fixture_state),
                "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
            }
            if family == "debian":
                command = [self.commands["sh"], str(hook), "configure"]
                if old is not None:
                    command.append(old)
            elif family == "fedora":
                # rpm runs %post with /bin/sh, which is Bash on Fedora, and $1
                # counts the installed instances: 1 on a first install, 2 on
                # an upgrade.
                command = [self.commands["bash"], "--posix", "--noprofile", "--norc", str(hook),
                           "1" if old is None else "2"]
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
            state["timer_armed"] = marker.exists()
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

    def test_upgrade_leaves_disabled_or_masked_reconcile_units_alone(self):
        # `systemctl start` runs a disabled unit too, so an upgrade must not
        # start or enable a self-heal unit an administrator turned off.
        for family in ("debian", "arch", "fedora"):
            for old in ("0.8.0", "0.11.3"):
                for choice in ("disabled", "masked", "masked-runtime"):
                    with self.subTest(family=family, old=old, choice=choice):
                        state = self.run_hook(family, ("enabled", True), ("enabled", True), old,
                                              reconcile=(choice, False))
                        for unit in RECONCILE:
                            self.assert_unit(state, unit, choice, False)

    def test_upgrade_runs_one_reconcile_only_when_its_service_is_enabled(self):
        for family in ("debian", "arch"):
            for enabled in ("enabled", "enabled-runtime"):
                with self.subTest(family=family, enabled=enabled):
                    state = self.run_hook(family, ("enabled", True), ("enabled", True),
                                          reconcile=(enabled, False))
                    self.assert_unit(state, "irlume-reconcile.service", enabled, True, starts=1)
                    self.assert_unit(state, "irlume-reconcile.path", enabled, False)
                    self.assert_unit(state, "irlume-reconcile.timer", enabled, False)

    def test_fedora_upgrade_starts_each_reconcile_unit_only_while_it_is_enabled(self):
        # Fedora's %post also starts the path and timer units on an upgrade,
        # so each one is checked on its own.
        for enabled in RECONCILE:
            for others in ("disabled", "masked"):
                with self.subTest(enabled=enabled, others=others):
                    state = self.run_hook("fedora", ("enabled", True), ("enabled", True),
                                          reconcile={unit: ("enabled" if unit == enabled
                                                            else others, False)
                                                     for unit in RECONCILE})
                    for unit in RECONCILE:
                        if unit == enabled:
                            self.assert_unit(state, unit, "enabled", True, starts=1)
                        else:
                            self.assert_unit(state, unit, others, False)

    def test_arch_upgrade_from_before_self_heal_enables_it_once(self):
        # Releases before 0.7.0 had no timer, so no marker either.
        for old in ("0.5.0-1", "0.6.0-1"):
            with self.subTest(old=old):
                state = self.run_hook("arch", ("enabled", True), ("disabled", False), old,
                                      reconcile=("disabled", False), timer_armed=False)
                for unit in RECONCILE:
                    self.assert_unit(state, unit, "enabled", True, starts=1)
                self.assertTrue(state["timer_armed"])

    def test_upgrade_from_before_the_timer_arms_it_once(self):
        # The one exception DISABLE.md names: 0.7.0 added the timer, and a
        # path or service left disabled on an older install is not evidence of
        # an administrator's choice (Fedora presets before 0.9.0 left the
        # service disabled, and the Debian and Fedora hooks never enabled the
        # path for upgraders from before it existed), so the timer is armed
        # once regardless.
        for family, old in (("debian", "0.6.1"), ("arch", "0.6.1-1"), ("fedora", "0.6.1")):
            with self.subTest(family=family):
                state = self.run_hook(family, ("enabled", True), ("enabled", True), old,
                                      reconcile={"irlume-reconcile.path": ("disabled", False),
                                                 "irlume-reconcile.timer": ("disabled", False),
                                                 "irlume-reconcile.service": ("disabled", False)},
                                      timer_armed=False)
                self.assert_unit(state, "irlume-reconcile.path", "disabled", False)
                self.assert_unit(state, "irlume-reconcile.service", "disabled", False)
                self.assert_unit(state, "irlume-reconcile.timer", "enabled", True, starts=1)
                self.assertTrue(state["timer_armed"])

    def test_arch_upgrade_after_an_install_keeps_a_disabled_timer_off(self):
        # post_install enables the timer and writes no marker, so the first
        # upgrade of any Arch install made since 0.7.0 finds none. That upgrade
        # must not take the marker's absence for an install older than the
        # timer and enable a timer the administrator has since disabled.
        for old in ("0.7.0-1", "0.14.0-1"):
            for others in ("enabled", "disabled"):
                with self.subTest(old=old, others=others):
                    state = self.run_hook("arch", ("enabled", True), ("enabled", True), old,
                                          reconcile={"irlume-reconcile.path": (others, False),
                                                     "irlume-reconcile.timer": ("disabled", False),
                                                     "irlume-reconcile.service": (others, False)},
                                          timer_armed=False)
                    self.assert_unit(state, "irlume-reconcile.timer", "disabled", False)
                    self.assert_unit(state, "irlume-reconcile.path", others, False)

    def test_first_install_enables_and_starts_the_reconcile_units(self):
        for family in ("debian", "arch", "fedora"):
            with self.subTest(family=family):
                state = self.run_hook(family, ("disabled", False), ("disabled", False), None,
                                      reconcile=("disabled", False))
                for unit in RECONCILE:
                    self.assert_unit(state, unit, "enabled", True, starts=1)

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

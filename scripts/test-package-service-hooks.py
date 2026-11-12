#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Execute package hooks with isolated command shims; never change host services.

Requires dpkg and vercmp so migration decisions use the native comparators.
The shell executes a copy with /var/lib/irlume and /run/systemd/system relocated
into the fixture to isolate the timer marker and manager-presence check;
service commands and branches are unchanged. Fedora's %post uses its one macro,
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
LIGHTDM_REFRESH = ("irlume-lightdm-refresh.path", "irlume-lightdm-refresh.timer",
                   "irlume-lightdm-refresh.service")
FEDORA_PRESET = [line.split()[1] for line in
                 (ROOT / "packaging/fedora/90-irlume.preset").read_text().splitlines()
                 if line.startswith("enable ")]
# Where to report a problem: what the Arch and Debian hooks print on a first
# install, the lines scripts/install.sh prints after a failure or for a daemon
# that is not active.
SECURITY_URL = "https://github.com/archledger/irlume/security/advisories/new"
CHOOSER_URL = "https://github.com/archledger/irlume/issues/new/choose"
WHERE_TO_REPORT = (
    "Security problem (a photo, video, mask or another person got in,",
    "face sign-in worked without your face, or face data was exposed),",
    "or not sure? Never post it publicly. Report it privately:",
    SECURITY_URL,
    "or the e-mail address in SECURITY.md.",
    f"Anything else: {CHOOSER_URL}",
)
ATTACH_A_REPORT = "Your own words are fine; attach the file `irlume support-report` writes."

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

if name == "systemctl" and state.get("fail_systemctl", False):
    status = 1
elif name == "systemctl":
    verb = args[0] if args else ""
    flags = [arg for arg in args[1:] if arg.startswith("-")]
    units = [arg for arg in args[1:] if not arg.startswith("-")]
    if verb == "daemon-reload" and not flags and not units:
        pass
    elif verb in {"disable", "stop"} and units and flags in ([], ["--now"]):
        for unit_name in units:
            unit = state["units"].get(unit_name)
            if unit is None:
                status = unexpected()
            else:
                if verb == "disable":
                    unit["enabled"] = "disabled"
                if verb == "stop" or "--now" in flags:
                    unit["active"] = False
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
    if state.get("parser_fails", False):
        print("synthetic AppArmor parser failure", file=sys.stderr)
        status = 1
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
                 timer_armed=True, hook="postinstall", action="configure", systemd=True,
                 fail_systemctl=False, dpkg_root=False, parser_fails=False):
        # reconcile is one (enabled, active) pair for all three units, or a
        # dict giving each unit its own. timer_armed=False leaves out the
        # one-time timer marker, as on an install from before 0.7.0 or an
        # Arch install that has not been upgraded since. parser_fails=True
        # makes apparmor_parser fail, the one case a hook may write to stderr.
        if isinstance(reconcile, tuple):
            reconcile = dict.fromkeys(RECONCILE, reconcile)
        with tempfile.TemporaryDirectory(prefix="irlume-hook-test-") as temp:
            directory = Path(temp)
            # A real marker under a private path works with both dash and Bash.
            # Do not override shell builtins: dash rejects a function named [.
            fixture_state = directory / "var/lib/irlume"
            fixture_state.mkdir(parents=True)
            runtime = directory / "run/systemd/system"
            if systemd:
                runtime.mkdir(parents=True)
            marker = fixture_state / ".reconcile-timer-armed"
            if timer_armed:
                marker.touch()
            if family == "fedora":
                text = self.fedora_post()
            else:
                text = (ROOT / (f"packaging/debian/{hook}.sh" if family == "debian"
                                else "packaging/arch/irlume.install")).read_text()
            script = directory / "hook.sh"
            script.write_text(text.replace("/var/lib/irlume", str(fixture_state))
                              .replace("/run/systemd/system", str(runtime)))
            state_path = directory / "state.json"
            state_path.write_text(json.dumps({
                "units": {
                    DAEMON: {"enabled": service[0], "active": service[1], "starts": 0, "restarts": 0},
                    SOCKET: {"enabled": socket[0], "active": socket[1], "starts": 0, "restarts": 0},
                    **{unit: {"enabled": reconcile[unit][0], "active": reconcile[unit][1],
                               "starts": 0, "restarts": 0} for unit in RECONCILE},
                    **{unit: {"enabled": "enabled", "active": True,
                               "starts": 0, "restarts": 0} for unit in (
                                   *LIGHTDM_REFRESH, "irlume-lightdm-prepare.service", "lightdm.service")},
                },
                "preset": FEDORA_PRESET, "calls": [], "errors": [],
                "fail_systemctl": fail_systemctl, "parser_fails": parser_fails,
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
                "DPKG_ROOT": str(directory / "offline-root") if dpkg_root else "",
            }
            if family == "debian":
                command = [self.commands["sh"], str(script), action]
                if old is not None:
                    command.append(old)
            elif family == "fedora":
                # rpm runs %post with /bin/sh, which is Bash on Fedora, and $1
                # counts the installed instances: 1 on a first install, 2 on
                # an upgrade.
                command = [self.commands["bash"], "--posix", "--noprofile", "--norc", str(script),
                           "1" if old is None else "2"]
            else:
                env["HOOK_SCRIPT"] = str(script)
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
            if not parser_fails:
                self.assertEqual(stderr, "", stdout)
            self.assertEqual(state["errors"], [], "unexpected or unsafe hook command")
            state["stdout"], state["stderr"] = stdout, stderr
            return state

    def assert_unit(self, state, unit, enabled, active, starts=0, restarts=0):
        self.assertEqual(state["units"][unit], {
            "enabled": enabled, "active": active, "starts": starts, "restarts": restarts,
        }, state["calls"])

    def test_debian_removal_stops_refresh_without_stopping_lightdm(self):
        state = self.run_hook("debian", ("enabled", True), ("enabled", True),
                              hook="preremove", action="remove")
        for unit in (DAEMON, SOCKET, *RECONCILE, *LIGHTDM_REFRESH):
            self.assertFalse(state["units"][unit]["active"], unit)
        for unit in ("lightdm.service", "irlume-lightdm-prepare.service"):
            self.assert_unit(state, unit, "enabled", True)
        triggers = state["calls"].index(["systemctl", "stop", *LIGHTDM_REFRESH[:2]])
        worker = state["calls"].index(["systemctl", "stop", LIGHTDM_REFRESH[2]])
        self.assertLess(triggers, worker)

    def test_debian_postremove_reloads_only_after_removal_or_purge(self):
        manifest = (ROOT / "packaging/debian/nfpm.yaml").read_text()
        self.assertIn("  postremove: ./postremove.sh", manifest)
        for action in ("remove", "purge", "upgrade", "failed-upgrade", "abort-install", "disappear"):
            with self.subTest(action=action):
                state = self.run_hook("debian", ("enabled", True), ("enabled", True),
                                      hook="postremove", action=action)
                self.assertEqual(state["calls"], [["systemctl", "daemon-reload"]]
                                 if action in ("remove", "purge") else [])

    def test_debian_removal_hooks_leave_offline_managers_alone(self):
        for hook in ("preremove", "postremove"):
            for options in ({"systemd": False}, {"dpkg_root": True}):
                with self.subTest(hook=hook, options=options):
                    state = self.run_hook("debian", ("enabled", True), ("enabled", True),
                                          hook=hook, action="remove", **options)
                    self.assertEqual(state["calls"], [])

    def test_debian_preremove_upgrade_preserves_every_unit(self):
        state = self.run_hook("debian", ("enabled", True), ("enabled", True),
                              hook="preremove", action="upgrade")
        self.assertEqual(state["calls"], [])

    def test_debian_removal_tolerates_an_unavailable_manager(self):
        for hook in ("preremove", "postremove"):
            with self.subTest(hook=hook):
                state = self.run_hook("debian", ("enabled", True), ("enabled", True),
                                      hook=hook, action="remove", fail_systemctl=True)
                self.assertTrue(state["calls"])

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

    def test_debian_modern_upgrade_without_marker_preserves_timer_state(self):
        # Native packages have the timer but do not write the universal
        # package's migration marker. Its absence must not undo an admin choice.
        for old in ("0.7.0", "0.7.0-1", "0.15.0~nightly-1", "1:0.6.1-1"):
            for enabled, active in (("disabled", False), ("disabled", True),
                                    ("enabled", False), ("enabled", True),
                                    ("enabled-runtime", False), ("masked", False),
                                    ("masked-runtime", False)):
                with self.subTest(old=old, enabled=enabled, active=active):
                    state = self.run_hook("debian", ("enabled", True), ("enabled", True), old,
                                          reconcile={"irlume-reconcile.path": ("disabled", False),
                                                     "irlume-reconcile.timer": (enabled, active),
                                                     "irlume-reconcile.service": ("disabled", False)},
                                          timer_armed=False)
                    self.assert_unit(state, "irlume-reconcile.timer", enabled, active)
                    self.assert_unit(state, "irlume-reconcile.path", "disabled", False)
                    self.assert_unit(state, "irlume-reconcile.service", "disabled", False)

    def test_debian_pre_timer_upgrade_respects_existing_migration_marker(self):
        for old in ("0.6.1", "0.6.1-2", "0.7.0~rc1"):
            for timer_armed in (False, True):
                with self.subTest(old=old, timer_armed=timer_armed):
                    state = self.run_hook("debian", ("enabled", True), ("enabled", True), old,
                                          reconcile=("disabled", False), timer_armed=timer_armed)
                    self.assert_unit(state, "irlume-reconcile.timer",
                                     "disabled" if timer_armed else "enabled", not timer_armed,
                                     starts=int(not timer_armed))
                    self.assert_unit(state, "irlume-reconcile.path", "disabled", False)
                    self.assert_unit(state, "irlume-reconcile.service", "disabled", False)
                    self.assertTrue(state["timer_armed"])

    def test_debian_first_install_without_marker_arms_timer(self):
        state = self.run_hook("debian", ("disabled", False), ("disabled", False), None,
                              reconcile=("disabled", False), timer_armed=False)
        for unit in RECONCILE:
            self.assert_unit(state, unit, "enabled", True, starts=1)
        self.assertTrue(state["timer_armed"])

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

    def test_first_install_says_where_to_report(self):
        block = "\n\n" + "\n".join((*WHERE_TO_REPORT, ATTACH_A_REPORT)) + "\n"
        for family in ("debian", "arch"):
            with self.subTest(family=family):
                state = self.run_hook(family, ("disabled", False), ("disabled", False), None)
                stdout = state["stdout"]
                self.assertEqual(stdout.count(block), 1, stdout)
                self.assertEqual(stdout.count(SECURITY_URL), 1, stdout)
                self.assertEqual(stdout.count(CHOOSER_URL), 1, stdout)
                self.assertLess(stdout.index("irlume installed. Next steps:"), stdout.index(block))

    def test_upgrade_does_not_repeat_where_to_report(self):
        for family, old, says in (("debian", "0.11.3", "irlume installed. Next steps:"),
                                  ("arch", "0.11.3-1", None),
                                  ("arch", "0.1.9-1", "irlume 0.2.0: the IR adapter was removed.")):
            with self.subTest(family=family, old=old):
                state = self.run_hook(family, ("enabled", True), ("enabled", True), old)
                stdout = state["stdout"]
                if says is not None:
                    self.assertIn(says, stdout)
                for text in (SECURITY_URL, CHOOSER_URL, WHERE_TO_REPORT[0], ATTACH_A_REPORT):
                    self.assertNotIn(text, stdout)

    def test_universal_deb_parser_failure_links_the_issue_chooser(self):
        for old in (None, "0.11.3"):
            with self.subTest(old=old):
                service = ("disabled", False) if old is None else ("enabled", True)
                state = self.run_hook("debian", service, service, old, parser_fails=True)
                stderr = state["stderr"]
                # The hook sends the parser's own output to stdout (2>&1).
                self.assertIn("synthetic AppArmor parser failure", state["stdout"])
                self.assertEqual(stderr.count("WARNING:"), 1, stderr)
                self.assertIn("the AppArmor profile did not load", stderr)
                self.assertIn("run unconfined", stderr)
                self.assertIn(f"Report the parser error above at\nirlume: {CHOOSER_URL}\n", stderr)
                self.assertNotIn(SECURITY_URL, stderr)
                # Not fatal: the daemon still starts on a first install and
                # restarts on an upgrade.
                self.assert_unit(state, DAEMON, "enabled", True, starts=int(old is None), restarts=1)


if __name__ == "__main__":
    unittest.main()

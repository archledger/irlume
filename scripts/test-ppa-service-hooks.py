#!/usr/bin/env python3
"""Generate real PPA maintainer hooks and execute them without host service access.

Requires Debian's debhelper and init-system-helpers. Generation uses the recipe's
native dh sequence; execution keeps deb-systemd-invoke real and confines its
policy helper, systemctl and enablement bookkeeping to private fixtures. This
checks package decisions, not systemd's dependency engine (use the VM matrix).
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DAEMON = "irlumed.service"
SOCKET = "irlumed.socket"
RECONCILE = ("irlume-reconcile.path", "irlume-reconcile.service", "irlume-reconcile.timer")
UNITS = (DAEMON, SOCKET, *RECONCILE)

# The real Debian wrapper decides which units reach systemctl and asks the real
# test policy executable first. Only the side effects at those boundaries are
# simulated. Unknown commands remain errors even if the maintainer hook uses
# `|| true`. No command ever falls back to a host service tool.
SHIM = r'''
import json
import os
from pathlib import Path
import sys

path = Path(os.environ["HOOK_STATE"])
state = json.loads(path.read_text())
name, args = Path(sys.argv[0]).name, sys.argv[1:]
state["calls"].append([name, *args])
status = 0

def unexpected():
    state["errors"].append([name, *args])
    return 99

if name == "systemctl":
    words = list(args)
    while words and words[0] in ("--system", "--quiet"):
        words.pop(0)
    verb = words.pop(0) if words else ""
    if words[:1] == ["--"]:
        words.pop(0)
    if verb == "daemon-reload" and not words:
        state["reloads"] += 1
    elif verb in ("is-enabled", "is-active") and len(words) == 1 and words[0] in state["units"]:
        unit = state["units"][words[0]]
        if verb == "is-enabled":
            print(unit["enabled"])
            status = 0 if unit["enabled"] in ("enabled", "enabled-runtime") else 1
        else:
            status = 0 if unit["active"] else 3
    elif verb in ("start", "restart", "try-restart", "stop") and words and all(u in state["units"] for u in words):
        for unit_name in words:
            unit = state["units"][unit_name]
            if verb == "stop":
                unit["active"] = False
                unit["stops"] += 1
            elif unit["enabled"] in ("masked", "masked-runtime"):
                status = 1
            elif verb != "try-restart" or unit["active"]:
                if unit["active"]:
                    unit["restarts"] += int(verb != "start")
                else:
                    unit["starts"] += 1
                unit["active"] = unit_name != "irlume-reconcile.service"
                state["activation_order"].append({"unit": unit_name, "prepared": state["prepared"],
                    "profile_loaded": state["profile_loaded"], "reloads": state["reloads"],
                    "enable_checked": unit["enable_checked"]})
    else:
        status = unexpected()
elif name == "deb-systemd-helper":
    words = list(args)
    if words[:1] == ["--quiet"]:
        words.pop(0)
    verb = words.pop(0) if words else ""
    if not words or any(u not in state["units"] for u in words):
        status = unexpected()
    elif verb == "was-enabled" and len(words) == 1:
        unit = state["units"][words[0]]
        status = 0 if state["fresh"] or unit["enabled"] in ("enabled", "enabled-runtime") else 1
    elif verb in ("unmask", "enable", "update-state", "purge"):
        for unit_name in words:
            unit = state["units"][unit_name]
            # deb-systemd-helper's unmask removes its own removal mask, not an
            # administrator's mask. Real mask preservation is also VM-tested.
            if verb in ("enable", "update-state"):
                unit["enable_checked"] = True
            if verb == "enable" and unit["enabled"] not in ("masked", "masked-runtime"):
                unit["enabled"] = "enabled"
            if verb == "purge":
                state["purged"].append(unit_name)
    else:
        status = unexpected()
elif name == "systemd-tmpfiles":
    words = list(args)
    if words and words[0].startswith("--root="):
        words.pop(0)
    if words == ["--create", "irlume.conf"]:
        state["prepared"] = True
    else:
        status = unexpected()
elif name == "apparmor_parser" and args == ["-r", "/etc/apparmor.d/usr.bin.irlumed"]:
    state["profile_loaded"] = True
elif name == "policy-rc.d" and len(args) == 2 and args[0] in state["units"] and args[1] in ("start", "restart", "try-restart", "stop"):
    status = state["policy"]
else:
    status = unexpected()
path.write_text(json.dumps(state))
sys.exit(status)
'''


def run(command, *, cwd, env):
    """Bound the complete subprocess group, including native helper children."""
    with subprocess.Popen(command, cwd=cwd, env=env, text=True,
                          stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=20)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
    if process.returncode:
        raise AssertionError(f"{command!r}: exit {process.returncode}\n{stdout}\n{stderr}")
    return stdout, stderr


def generation_step(output):
    """Map native dry-run output to one fixed, explicitly permitted command."""
    choices = []
    for line in output.splitlines():
        # Avoid accepting dh_installsystemduser as the system-unit step.
        if not re.search(r"\b(?:override_)?dh_installsystemd(?:\b|[-_])", line):
            continue
        words = shlex.split(line)
        if words == ["dh_installsystemd"]:
            choices.append(["dh_installsystemd"])
        elif words == ["debian/rules", "override_dh_installsystemd"]:
            choices.append(["make", "-f", "debian/rules", "override_dh_installsystemd"])
        else:
            raise AssertionError(f"unrecognized system-unit generation step: {line!r}")
    if len(choices) != 1:
        raise AssertionError(f"expected exactly one system-unit generation step: {choices!r}")
    return choices[0]


class PpaServiceHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.commands = {}
        for name in ("dh", "dh_installsystemd", "dh_installtmpfiles", "dh_installdeb",
                     "deb-systemd-invoke", "deb-systemd-helper", "make", "sh", "cat"):
            executable = shutil.which(name)
            if executable is None:
                raise RuntimeError(f"required PPA test dependency missing: {name}")
            cls.commands[name] = executable
        temporary = tempfile.TemporaryDirectory(prefix="irlume-ppa-generation-")
        cls.addClassCleanup(temporary.cleanup)
        cls.generated = Path(temporary.name)
        shutil.copytree(ROOT / "packaging/ppa/debian", cls.generated / "debian")
        # The source-package builder normally generates this metadata. Its
        # version/date are deliberately synthetic and do not affect hook logic.
        (cls.generated / "debian/changelog").write_text(
            "irlume (1) unstable; urgency=medium\n\n"
            "  * Disposable hook-generation fixture.\n\n"
            " -- Test <test@example.invalid>  Thu, 01 Jan 1970 00:00:00 +0000\n")
        units = cls.generated / "debian/irlume/usr/lib/systemd/system"
        units.mkdir(parents=True)
        for name in UNITS:
            shutil.copy2(ROOT / "packaging/systemd" / name, units / name)
        tmpfiles = cls.generated / "debian/irlume/usr/lib/tmpfiles.d"
        tmpfiles.mkdir()
        shutil.copy2(ROOT / "packaging/tmpfiles.d/irlume.conf", tmpfiles / "irlume.conf")
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": str(cls.generated)}
        sequence, _ = run([cls.commands["dh"], "binary", "--no-act"], cwd=cls.generated, env=env)
        selected = generation_step(sequence)
        print("PPA native generation:", " ".join(selected), flush=True)
        run([cls.commands["dh_installtmpfiles"]], cwd=cls.generated, env=env)
        run([cls.commands[selected[0]], *selected[1:]], cwd=cls.generated, env=env)
        run([cls.commands["dh_installdeb"]], cwd=cls.generated, env=env)
        cls.hooks = {name: (cls.generated / "debian/irlume/DEBIAN" / name).read_text()
                     for name in ("postinst", "prerm", "postrm")}
        # A --no-start-only regression also generates an unwanted upgrade stop.
        preinst = cls.generated / "debian/irlume/DEBIAN/preinst"
        if preinst.exists():
            cls.hooks["preinst"] = preinst.read_text()
        cls.invoke = Path(cls.commands["deb-systemd-invoke"]).read_text()
        policy_path = "'/usr/sbin/policy-rc.d'"
        if cls.invoke.count(policy_path) != 1:
            raise AssertionError("unsupported deb-systemd-invoke policy path; inspect installed helper")
        cls.invoke = cls.invoke.replace(policy_path, "$ENV{'HOOK_POLICY'}")

    def run_hook(self, service=("enabled", False), socket=("enabled", False),
                 *, old="0.11.3-1", action="configure", policy=0,
                 systemd=True, dpkg_root=False, hook="postinst"):
        with tempfile.TemporaryDirectory(prefix="irlume-ppa-hook-") as temporary:
            directory = Path(temporary)
            runtime = directory / "run/systemd/system"
            if systemd:
                runtime.mkdir(parents=True)
            boundary = directory / "commands"
            boundary.mkdir()
            state_path = directory / "state.json"
            units = {}
            for name in UNITS:
                if name == DAEMON:
                    enabled, active = service
                elif name == SOCKET:
                    enabled, active = socket
                else:
                    enabled, active = "enabled", False
                units[name] = {"enabled": enabled, "active": active,
                               "starts": 0, "restarts": 0, "stops": 0, "enable_checked": False}
            state_path.write_text(json.dumps({"units": units, "calls": [], "errors": [],
                "fresh": old is None, "policy": policy, "prepared": False, "profile_loaded": False,
                "reloads": 0, "activation_order": [], "purged": []}))
            for name in ("systemctl", "deb-systemd-helper", "systemd-tmpfiles", "apparmor_parser", "policy-rc.d"):
                path = boundary / name
                path.write_text(f"#!{sys.executable}\n{SHIM}")
                path.chmod(0o700)
            invoke = boundary / "deb-systemd-invoke"
            invoke.write_text(self.invoke)
            invoke.chmod(0o700)
            (boundary / "cat").symlink_to(self.commands["cat"])
            text = self.hooks[hook]
            # Relocate filesystem probes, never action decisions. Keep the
            # original guards executable for present/absent/offline cases.
            text = text.replace("/run/systemd/system", str(runtime))
            text = text.replace("/usr/bin/deb-systemd-helper", str(boundary / "deb-systemd-helper"))
            # Do not permit an absolute service executable to escape PATH.
            if re.search(r"/(?:usr/)?s?bin/(?:systemctl|deb-systemd-invoke|systemd-tmpfiles|apparmor_parser)\b", text):
                raise AssertionError("absolute service command outside test boundary")
            script = directory / hook
            script.write_text(text)
            env = {"PATH": str(boundary), "HOOK_STATE": str(state_path),
                   "HOOK_POLICY": str(boundary / "policy-rc.d"), "LC_ALL": "C",
                   "DPKG_ROOT": str(directory / "offline-root") if dpkg_root else "",
                   "PYTHONDONTWRITEBYTECODE": "1"}
            args = [self.commands["sh"], str(script), action]
            if old is not None:
                args.append(old)
            run(args, cwd=directory, env=env)
            state = json.loads(state_path.read_text())
            self.assertEqual(state["errors"], [], "unexpected or unsafe hook command")
            return state

    def assert_unit(self, state, unit, enabled, active, *, starts=0, restarts=0, stops=0):
        actual = {k: v for k, v in state["units"][unit].items() if k != "enable_checked"}
        self.assertEqual(actual, {"enabled": enabled, "active": active,
                                 "starts": starts, "restarts": restarts, "stops": stops}, state["calls"])

    def test_upgrade_preserves_enabled_stopped_daemon_and_socket(self):
        state = self.run_hook()
        self.assert_unit(state, DAEMON, "enabled", False)
        self.assert_unit(state, SOCKET, "enabled", False)

    def test_upgrade_preserves_independently_disabled_socket(self):
        state = self.run_hook(socket=("disabled", False))
        self.assert_unit(state, DAEMON, "enabled", False)
        self.assert_unit(state, SOCKET, "disabled", False)

    def test_upgrade_preserves_disabled_stopped_units(self):
        state = self.run_hook(("disabled", False), ("disabled", False))
        self.assert_unit(state, DAEMON, "disabled", False)
        self.assert_unit(state, SOCKET, "disabled", False)

    def test_upgrade_restarts_running_units_without_reenabling_disabled_units(self):
        for enabled in ("enabled", "disabled"):
            with self.subTest(enabled=enabled):
                state = self.run_hook((enabled, True), (enabled, True))
                for unit in (DAEMON, SOCKET):
                    self.assert_unit(state, unit, enabled, True, restarts=1)

    def test_upgrade_preserves_administrator_masks(self):
        for mask in ("masked", "masked-runtime"):
            for service in (mask, "enabled"):
                with self.subTest(mask=mask, service=service):
                    state = self.run_hook((service, False), (mask, False))
                    self.assert_unit(state, DAEMON, service, False)
                    self.assert_unit(state, SOCKET, mask, False)

    def test_first_install_starts_after_preparation_enablement_and_reload(self):
        state = self.run_hook(("disabled", False), ("disabled", False), old=None)
        for unit in UNITS:
            self.assert_unit(state, unit, "enabled", unit != "irlume-reconcile.service", starts=1)
        self.assertEqual(len(state["activation_order"]), 5)
        for event in state["activation_order"]:
            self.assertTrue(event["prepared"], event)
            self.assertTrue(event["profile_loaded"], event)
            self.assertTrue(event["enable_checked"], event)
            self.assertGreater(event["reloads"], 0, event)

    def test_upgrade_keeps_reconciliation_activation(self):
        state = self.run_hook()
        # In particular, the enabled oneshot must still run on upgrade, even
        # though it is normally inactive between its executions.
        for unit in RECONCILE:
            self.assert_unit(state, unit, "enabled", unit != "irlume-reconcile.service", starts=1)

    def test_policy_refusal_prevents_install_and_upgrade_activation(self):
        for old in (None, "0.11.3-1"):
            for active in (False, True):
                with self.subTest(old=old, active=active):
                    state = self.run_hook(("enabled", active), ("enabled", active), old=old, policy=101)
                    for unit in (DAEMON, SOCKET):
                        self.assert_unit(state, unit, "enabled", active)
                    self.assertEqual(state["activation_order"], [])
                    self.assertTrue(any(call[0] == "policy-rc.d" for call in state["calls"]))

    def test_missing_systemd_prevents_runtime_actions(self):
        for old in (None, "0.11.3-1"):
            with self.subTest(old=old):
                state = self.run_hook(old=old, systemd=False)
                self.assertEqual(state["activation_order"], [])
                self.assertFalse(any(call[0] in ("systemctl", "policy-rc.d") for call in state["calls"]))

    def test_offline_root_does_not_activate_daemon_or_socket(self):
        for old in (None, "0.11.3-1"):
            with self.subTest(old=old):
                state = self.run_hook(old=old, dpkg_root=True)
                for unit in (DAEMON, SOCKET):
                    self.assert_unit(state, unit, "enabled", False)
                # Existing reconciliation autoscripts keep their native
                # behavior; this assertion covers only the changed pair.
                self.assertFalse(any(event["unit"] in (DAEMON, SOCKET)
                                     for event in state["activation_order"]))

    def test_remove_stops_every_unit_and_respects_policy(self):
        for policy in (0, 101):
            with self.subTest(policy=policy):
                state = self.run_hook(("enabled", True), ("enabled", True),
                                      hook="prerm", action="remove", policy=policy)
                for unit in (DAEMON, SOCKET):
                    self.assert_unit(state, unit, "enabled", policy == 101, stops=int(policy == 0))
                for unit in RECONCILE:
                    self.assertEqual(state["units"][unit]["stops"], int(policy == 0))

    def test_upgrade_does_not_stop_units_before_replacement(self):
        hooks = ["prerm"] + (["preinst"] if "preinst" in self.hooks else [])
        for hook in hooks:
            with self.subTest(hook=hook):
                state = self.run_hook(("enabled", True), ("enabled", True), hook=hook, action="upgrade")
                for unit in (DAEMON, SOCKET):
                    self.assert_unit(state, unit, "enabled", True)
                self.assertTrue(all(unit["stops"] == 0 for unit in state["units"].values()))

    def test_remove_reloads_and_purge_covers_every_unit_once(self):
        removed = self.run_hook(hook="postrm", action="remove")
        self.assertGreater(removed["reloads"], 0)
        purged = self.run_hook(hook="postrm", action="purge")
        self.assertCountEqual(purged["purged"], UNITS)
        self.assertEqual(purged["activation_order"], [])

    def test_abort_recovery_only_restarts_an_active_pair_with_an_old_version(self):
        # Match the selected debhelper no-start recovery policy explicitly;
        # aborted removal does not force a stopped daemon back into service.
        for action in ("abort-upgrade", "abort-deconfigure", "abort-remove"):
            for old in (None, "0.11.3-1"):
                for active in (False, True):
                    with self.subTest(action=action, old=old, active=active):
                        state = self.run_hook(("enabled", active), ("enabled", active),
                                              action=action, old=old)
                        for unit in (DAEMON, SOCKET):
                            self.assert_unit(state, unit, "enabled", active,
                                             restarts=int(active and old is not None))

    def test_native_generation_selection_rejects_unknown_or_duplicate_steps(self):
        for sequence in ("", "dh_installsystemd\ndh_installsystemd\n",
                         "debian/rules override_dh_installsystemd-arch\n",
                         "dh_installsystemd; systemctl start irlumed.service\n"):
            with self.subTest(sequence=sequence):
                with self.assertRaises(AssertionError):
                    generation_step(sequence)


if __name__ == "__main__":
    unittest.main()

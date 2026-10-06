#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Stage only the LightDM install commands and verify the assembled units offline."""

from pathlib import Path
import os
import shlex
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
UNITS = (
    "irlume-lightdm-prepare.service", "irlume-lightdm-refresh.service",
    "irlume-lightdm-refresh.path", "irlume-lightdm-refresh.timer",
)
DROPIN = "lightdm.service.d/50-irlume-pam.conf"
EXPECTED = (*UNITS, DROPIN)


class Packaging(unittest.TestCase):
    def test_fhs_lanes_install_every_file_at_the_real_destination(self):
        for lane in ("packaging/fedora/irlume.spec", "packaging/arch/PKGBUILD", "packaging/ppa/debian/rules"):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as temp:
                stage = Path(temp)
                text = (ROOT / lane).read_text().replace("\\\n", " ")
                commands = [line.strip() for line in text.splitlines()
                            if line.strip().startswith("install ")
                            and ("packaging/systemd/irlume-lightdm-" in line
                                 or "packaging/lightdm/50-irlume-pam.conf" in line)]
                self.assertEqual(len(commands), len(EXPECTED))
                for command in commands:
                    command = command.replace("%{buildroot}", temp).replace("%{_unitdir}", "/usr/lib/systemd/system")
                    command = command.replace("$pkgdir", temp).replace("debian/irlume/usr/", temp + "/usr/")
                    words = shlex.split(command)
                    self.assertTrue(Path(words[-1]).is_relative_to(stage))
                    subprocess.run(words, cwd=ROOT, check=True)
                for name in EXPECTED:
                    actual = stage / "usr/lib/systemd/system" / name
                    source = ROOT / ("packaging/lightdm/50-irlume-pam.conf" if name == DROPIN else "packaging/systemd/" + name)
                    self.assertEqual(actual.read_bytes(), source.read_bytes())
        spec = (ROOT / "packaging/fedora/irlume.spec").read_text().split("%files", 1)[1]
        for name in EXPECTED:
            self.assertIn("%{_unitdir}/" + name, spec)

    def test_nfpm_owns_all_five_destinations(self):
        lane = ROOT / "packaging/debian/nfpm.yaml"
        entries = yaml.safe_load(lane.read_text())["contents"]
        for name in EXPECTED:
            matches = [entry for entry in entries if entry.get("dst") == "/usr/lib/systemd/system/" + name]
            self.assertEqual(len(matches), 1, name)
            self.assertTrue((lane.parent / matches[0]["src"]).is_file())

    def test_source_installer_binds_helpers_to_usr_local(self):
        text = (ROOT / "scripts/install-host.sh").read_text()
        block = text.split("# The private PAM view is prepared before LightDM", 1)[1].split("systemctl daemon-reload", 1)[0]
        block = "# The private PAM view is prepared before LightDM" + block
        with tempfile.TemporaryDirectory() as temp:
            block = block.replace("/etc/systemd/system", temp + "/etc/systemd/system")
            for module_dir in ("/usr/lib64/security", "/usr/lib/security", "/usr/lib/x86_64-linux-gnu/security", "/lib/x86_64-linux-gnu/security"):
                block = block.replace(module_dir, temp + module_dir)
            module_dir = Path(temp) / "usr/lib64/security"
            module_dir.mkdir(parents=True)
            (module_dir / "pam_permit.so").write_bytes(b"synthetic installed PAM directory")
            module = Path(temp) / "module.so"
            module.write_bytes(b"synthetic module payload")
            block = block.replace('"$REPO/target/release/libpam_irlume_view.so"', shlex.quote(str(module)))
            subprocess.run(["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--bind", temp, temp,
                            "--dev", "/dev", "bash", "-eu", "-c", block], env={**os.environ, "REPO": str(ROOT)}, check=True)
            self.assertEqual((module_dir / "pam_irlume_view.so").read_bytes(), module.read_bytes())
            units = Path(temp) / "etc/systemd/system"
            for name in EXPECTED:
                actual = (units / name).read_text()
                self.assertNotIn("ExecStart=/usr/bin/irlume", actual)
                self.assertNotIn("ExecStartPre=/usr/bin/irlume", actual)
            self.assertIn("ExecStart=/usr/local/bin/irlume login lightdm-prestart", (units / UNITS[0]).read_text())

    def test_session_module_is_installed_in_every_fhs_lane(self):
        for lane, relative in (("packaging/fedora/irlume.spec", "usr/lib64/security/pam_irlume_view.so"),
                               ("packaging/arch/PKGBUILD", "usr/lib/security/pam_irlume_view.so"),
                               ("packaging/ppa/debian/rules", "usr/lib/x86_64-linux-gnu/security/pam_irlume_view.so")):
            with self.subTest(lane=lane), tempfile.TemporaryDirectory() as temp:
                payload = Path(temp) / "module.so"
                payload.write_bytes(b"synthetic module payload")
                text = (ROOT / lane).read_text().replace("\\\n", " ")
                commands = [line.strip() for line in text.splitlines() if line.strip().startswith("install ") and "target/release/libpam_irlume_view.so" in line]
                self.assertEqual(len(commands), 1)
                command = commands[0].replace("%{buildroot}", temp).replace("%{_libdir}", "/usr/lib64")
                command = command.replace("$pkgdir", temp).replace("debian/irlume/usr/", temp + "/usr/")
                command = command.replace("$(DEB_HOST_MULTIARCH)", "x86_64-linux-gnu")
                words = shlex.split(command)
                words[-2] = str(payload)
                self.assertEqual(Path(words[-1]), Path(temp) / relative)
                subprocess.run(words, check=True)
                self.assertEqual(Path(words[-1]).read_bytes(), payload.read_bytes())
        entries = yaml.safe_load((ROOT / "packaging/debian/nfpm.yaml").read_text())["contents"]
        self.assertEqual([e["dst"] for e in entries if e.get("src", "").endswith("/libpam_irlume_view.so")],
                         ["/usr/lib/x86_64-linux-gnu/security/pam_irlume_view.so"])

    def test_assembled_unit_requires_preparation_and_rejects_a_mask(self):
        with tempfile.TemporaryDirectory() as temp:
            units = Path(temp)
            for name in UNITS:
                text = (ROOT / "packaging/systemd" / name).read_text()
                # Syntax and dependency jobs only; no installed binary is run.
                (units / name).write_text(text.replace("/usr/bin/irlume", "/usr/bin/true"))
            (units / "lightdm.service").write_text("[Unit]\nDescription=synthetic LightDM\n[Service]\nExecStart=/usr/bin/true\n")
            (units / "lightdm.service.d").mkdir()
            dropin = (ROOT / "packaging/lightdm/50-irlume-pam.conf").read_text()
            self.assertIn("Requires=irlume-lightdm-prepare.service", dropin)
            self.assertIn("After=irlume-lightdm-prepare.service", dropin)
            self.assertNotIn("irlumed", "\n".join(line for line in dropin.splitlines() if not line.startswith("#")))
            (units / DROPIN).write_text(dropin.replace("/usr/bin/irlume", "/usr/bin/true"))
            env = {**os.environ, "SYSTEMD_UNIT_PATH": str(units) + ":/usr/lib/systemd/system"}
            command = ["systemd-analyze", "verify", str(units / "lightdm.service"), *(str(units / name) for name in UNITS)]
            good = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            (units / UNITS[0]).unlink()
            (units / UNITS[0]).symlink_to("/dev/null")
            masked = subprocess.run(command[:3], env=env, capture_output=True, text=True)
            self.assertNotEqual(masked.returncode, 0, masked.stderr)
            self.assertIn("masked", masked.stderr)

    def test_unit_design_pins(self):
        # systemd.service(257) ExecStartPre=: an unprefixed failing command
        # makes the unit fail, so the view check must carry no "-", "+",
        # ":" or "!" prefix. systemd.unit(257) Requires=/After=: a failed
        # or masked preparation unit stops the LightDM start.
        dropin = (ROOT / "packaging/lightdm/50-irlume-pam.conf").read_text()
        prefixes = ("-", "+", ":", "!")
        check = [line for line in dropin.splitlines() if line.startswith("ExecStartPre=")]
        self.assertEqual(len(check), 1)
        self.assertFalse(check[0][len("ExecStartPre="):][0] in prefixes, check[0])
        for bind in ("BindReadOnlyPaths=/etc/pam.d:/run/irlume-lightdm-source/etc",
                     "BindReadOnlyPaths=-/usr/lib/pam.d:/run/irlume-lightdm-source/vendor",
                     "BindReadOnlyPaths=/run/irlume-lightdm/pam.d:/etc/pam.d",
                     "BindReadOnlyPaths=/run/irlume-lightdm",
                     "ExecPaths=/run/irlume-lightdm"):
            self.assertIn(bind, dropin)

        prepare = (ROOT / "packaging/systemd" / UNITS[0]).read_text()
        directives = [line for line in prepare.splitlines() if line and not line.startswith(("#", "["))]
        self.assertIn("Type=oneshot", directives)
        self.assertIn("TimeoutStartSec=3s", directives)
        self.assertFalse([line for line in directives if "RemainAfterExit" in line], prepare)
        self.assertIn("login lightdm-prestart", prepare)
        self.assertNotIn("irlumed", prepare)

        # systemd.path(257): multiple PathModified= directives accumulate, and
        # watching the directories catches files replaced by rename, which the
        # reconcile path unit's file watches miss.
        path_unit = (ROOT / "packaging/systemd" / UNITS[2]).read_text()
        self.assertIn("PathModified=/etc/pam.d", path_unit)
        self.assertIn("PathModified=/usr/lib/pam.d", path_unit)

        refresh = (ROOT / "packaging/systemd" / UNITS[1]).read_text()
        timer = (ROOT / "packaging/systemd" / UNITS[3]).read_text()
        self.assertIn("login lightdm-refresh", refresh)
        self.assertNotIn("irlumed", refresh)
        self.assertIn("OnUnitInactiveSec=30s", timer)



if __name__ == "__main__":
    unittest.main()

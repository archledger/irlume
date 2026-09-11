#!/usr/bin/env python3
"""Offline desktop payload checks; never launch irlume or a terminal."""
import configparser
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
APP_ID = "io.github.archledger.Irlume"
DESKTOP = f"{APP_ID}.desktop"
ICON = f"{APP_ID}.svg"
ASSETS = {
    DESKTOP: f"applications/{DESKTOP}",
    ICON: f"icons/hicolor/scalable/apps/{ICON}",
}


def commands(path):
    text = (ROOT / path).read_text()
    return [line.strip() for line in re.sub(r"\\\n\s*", " ", text).splitlines()
            if not line.lstrip().startswith("#")]


class DesktopIntegration(unittest.TestCase):
    def test_launcher_is_a_direct_unprivileged_terminal_command(self):
        path = ROOT / "packaging/desktop" / DESKTOP
        self.assertTrue(path.is_file(), "missing application-menu launcher")
        config = configparser.ConfigParser(interpolation=None)
        config.optionxform = str
        config.read(path)
        self.assertEqual(config.sections(), ["Desktop Entry"])
        entry = config["Desktop Entry"]
        self.assertEqual(entry["Type"], "Application")
        self.assertEqual(entry["Exec"], "irlume tui")
        self.assertEqual(entry["TryExec"], "irlume")
        self.assertEqual(entry["Terminal"], "true")
        self.assertEqual(entry["Icon"], APP_ID)
        self.assertEqual(entry["Categories"], "Settings;")
        self.assertNotIn("DBusActivatable", entry)
        self.assertNotIn("Actions", entry)
        self.assertNotIn("OnlyShowIn", entry)
        self.assertNotIn("NoDisplay", entry)
        self.assertNotIn("Hidden", entry)
        subprocess.run(["desktop-file-validate", str(path)], check=True)

    def test_icon_is_self_contained_svg(self):
        path = ROOT / "packaging/desktop" / ICON
        self.assertTrue(path.is_file(), "missing application icon")
        tree = ET.parse(path)
        self.assertEqual(tree.getroot().tag, "{http://www.w3.org/2000/svg}svg")
        for node in tree.iter():
            self.assertNotIn(node.tag.rsplit("}", 1)[-1], ["script", "image", "foreignObject"])
            self.assertFalse(any(key.endswith("href") for key in node.attrib))

    def test_all_supported_install_recipes_stage_the_shared_payload(self):
        lanes = {
            "packaging/fedora/irlume.spec": "%{buildroot}%{_datadir}",
            "packaging/arch/PKGBUILD": "$pkgdir/usr/share",
            "packaging/ppa/debian/rules": "debian/irlume/usr/share",
            "nix/package.nix": "$out/share",
            "scripts/install-host.sh": "/usr/local/share",
        }
        with tempfile.TemporaryDirectory(prefix="irlume-desktop-") as td:
            for lane, prefix in lanes.items():
                for name, relative in ASSETS.items():
                    with self.subTest(lane=lane, asset=name):
                        rows = [shlex.split(line) for line in commands(lane)
                                if line.startswith("install ")
                                and (line.endswith(name + '"') or line.endswith(name))]
                        rows = [row for row in rows if row[-1] == f"{prefix}/{relative}"]
                        self.assertEqual(len(rows), 1, f"missing/duplicate installed {relative}")
                        args = rows[0]
                        source = args[-2].replace("$REPO/", "")
                        self.assertEqual(source, f"packaging/desktop/{name}")
                        dest = Path(td) / lane.replace("/", "_") / relative
                        subprocess.run([*args[:-2], str(ROOT / source), str(dest)], check=True)
                        self.assertEqual(dest.read_bytes(), (ROOT / source).read_bytes())
                        self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o644)

    def test_debian_manifest_and_rpm_ownership_include_both_assets(self):
        manifest = (ROOT / "packaging/debian/nfpm.yaml").read_text()
        spec = (ROOT / "packaging/fedora/irlume.spec").read_text()
        self.assertRegex(spec, r"(?m)^Requires:\s+hicolor-icon-theme$")
        files = spec.split("\n%files\n", 1)[1].split("\n%files selinux", 1)[0]
        for name, relative in ASSETS.items():
            with self.subTest(asset=name):
                self.assertRegex(manifest, re.escape(f"- src: ../desktop/{name}")
                                 + r"\s+" + re.escape(f"dst: /usr/share/{relative}"))
                self.assertIn(f"%{{_datadir}}/{relative}", files.splitlines())

    def test_prefix_specific_launchers_bind_the_installed_binary(self):
        nix = (ROOT / "nix/package.nix").read_text()
        self.assertIn("--replace-fail 'Exec=irlume tui' \"Exec=$out/bin/irlume tui\"", nix)
        self.assertIn("--replace-fail 'TryExec=irlume' \"TryExec=$out/bin/irlume\"", nix)
        source = (ROOT / "scripts/install-host.sh").read_text()
        self.assertIn("s|^Exec=irlume tui$|Exec=/usr/local/bin/irlume tui|", source)
        self.assertIn("s|^TryExec=irlume$|TryExec=/usr/local/bin/irlume|", source)

        # Execute the installer's actual rewrite against a disposable file.
        with tempfile.TemporaryDirectory(prefix="irlume-local-launcher-") as td:
            path = Path(td) / DESKTOP
            path.write_bytes((ROOT / "packaging/desktop" / DESKTOP).read_bytes())
            rewrite = [shlex.split(line) for line in commands("scripts/install-host.sh")
                       if line.startswith("sed -i ") and line.endswith(DESKTOP)]
            self.assertEqual(len(rewrite), 1)
            subprocess.run([*rewrite[0][:-1], str(path)], check=True)
            config = configparser.ConfigParser(interpolation=None)
            config.read(path)
            self.assertEqual(config["Desktop Entry"]["Exec"], "/usr/local/bin/irlume tui")
            self.assertEqual(config["Desktop Entry"]["TryExec"], "/usr/local/bin/irlume")
            subprocess.run(["desktop-file-validate", str(path)], check=True)

    def test_source_removal_matches_only_the_source_installer_assets(self):
        source = (ROOT / "crates/irlume-cli/src/uninstall.rs").read_text()
        self.assertIn('remove_source_desktop_files(Path::new("/usr/local/share"))', source)
        body = source.split("fn remove_source_desktop_files(", 1)[1].split("\n}", 1)[0]
        paths = re.findall(r'"((?:applications|icons)/[^"]+)"', body)
        self.assertEqual(sorted(paths), sorted(ASSETS.values()))


if __name__ == "__main__":
    unittest.main()

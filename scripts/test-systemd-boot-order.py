"""Check the packaged boot-order contract; no services or host files are changed."""

import configparser
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UNITS = ROOT / "packaging/systemd"


def read_metadata(text):
    # These sections currently use single assignments. Reject duplicates rather
    # than silently discarding dependencies that systemd would accumulate.
    lines = []
    selected = False
    for line in text.splitlines():
        if line.strip().startswith("["):
            selected = line.strip() in ("[Unit]", "[Install]")
        if selected:
            lines.append(line)
    unit = configparser.ConfigParser(interpolation=None)
    unit.optionxform = str
    unit.read_string("\n".join(lines))
    return unit


def read_unit(name):
    return read_metadata((UNITS / name).read_text())


class BootOrdering(unittest.TestCase):
    def setUp(self):
        self.daemon = read_unit("irlumed.service")
        self.reconcile = read_unit("irlume-reconcile.service")

    def test_daemon_does_not_wait_for_the_target_that_waits_for_reconciliation(self):
        # Target units normally wait for services in their Wants set. If the
        # daemon waits for that target, reconciliation cannot obtain its caps.
        self.assertNotIn(
            "multi-user.target", self.daemon["Unit"].get("After", "").split()
        )

    def test_reconciliation_waits_for_the_daemon_start_job(self):
        self.assertIn(
            "irlumed.service", self.reconcile["Unit"].get("After", "").split()
        )
        self.assertNotIn(
            "multi-user.target", self.reconcile["Unit"].get("After", "").split()
        )

    def test_ordering_does_not_force_a_disabled_daemon_to_start(self):
        # After orders jobs already in the transaction; requirements would
        # newly activate a daemon the administrator may have disabled.
        for key in ("Wants", "Requires", "BindsTo", "Upholds"):
            with self.subTest(dependency=key):
                self.assertNotIn(
                    "irlumed.service", self.reconcile["Unit"].get(key, "").split()
                )

    def test_boot_activation_and_default_dependencies_are_retained(self):
        for unit in (self.daemon, self.reconcile):
            with self.subTest(description=unit["Unit"]["Description"]):
                self.assertIn("multi-user.target", unit["Install"]["WantedBy"].split())
                self.assertNotIn(
                    unit["Unit"].get("DefaultDependencies", "yes").lower(),
                    {"no", "false", "off", "0"},
                )

    def test_daemon_restart_does_not_stop_reconciliation(self):
        self.assertNotIn(
            "irlumed.service", self.reconcile["Unit"].get("PartOf", "").split()
        )

    def test_dependency_duplicates_cannot_hide_an_earlier_assignment(self):
        for key in ("After", "Wants", "Requires"):
            with (
                self.subTest(key=key),
                self.assertRaises(configparser.DuplicateOptionError),
            ):
                read_metadata(f"[Unit]\n{key}=irlumed.service\n{key}=basic.target\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)

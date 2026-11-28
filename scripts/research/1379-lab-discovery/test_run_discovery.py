import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import run_discovery as rd


NONCE = "0123456789abcdef0123456789abcdef"
BOOT_INPUTS = ("guest/cgroup_device.c", "guest/lab.h")


def run_build(root: Path, linux: Path, libcamera: Path, out: Path) -> subprocess.CompletedProcess:
    """Run the build script with a fake git that reports clean pinned checkouts."""
    tools = root / "bin"
    tools.mkdir(exist_ok=True)
    git = tools / "git"
    git.write_text(
        "#!/bin/sh\n[ \"$1\" = -C ] || exit 1\ncase \"$3\" in\n"
        f"rev-parse) [ \"$2\" = '{linux}' ] && echo 988117cc1bb17338c586a4e21ade88b5397eac33 ||"
        " echo df8e348d64b4932a0676256ed24f0da3ee9438bc;;\n"
        "status) ;;\ndescribe) echo v0.8.0;;\n*) exit 1;;\nesac\n")
    (tools / "bc").write_text("#!/bin/sh\n")
    for tool in (git, tools / "bc"):
        tool.chmod(0o700)
    return subprocess.run(
        ("/usr/bin/bash", str(rd.HERE / "build_discovery_guest.sh"), str(linux), str(libcamera), str(out)),
        text=True, capture_output=True, timeout=20, env={**os.environ, "PATH": f"{tools}:/usr/bin"})


def serial(case, events, effects=(), topology=(), nonce=NONCE, dropped=0, count=None):
    events = tuple(e.replace("{ipa}", "0" * 64) for e in events)
    prefix = f"{rd.PROTOCOL} {nonce} "
    lines = ["[    0.000000] Linux version 7.3.5 (guest)"]
    lines += [prefix + event for event in events]
    lines += [prefix + "TOPOLOGY " + record for record in topology]
    lines += [prefix + f"EFFECT {seq} {effect}" for seq, effect in effects]
    total = len(effects) if count is None else count
    lines.append(prefix + f"EFFECTS_END {total} dropped={dropped}")
    return "\n".join(lines) + "\n"


def sim_controls(**overrides):
    effects = [(i + 1, effect) for i, effect in enumerate(rd.expected_effects("sim-controls"))]
    args = {"case": "sim-controls", "events": rd.CASES["sim-controls"].events, "effects": effects}
    args.update(overrides)
    return serial(**args)


def numbered(records):
    return [(i + 1, e) for i, e in enumerate(records)]


def stock(**overrides):
    args = {"case": "stock-baseline", "events": rd.CASES["stock-baseline"].events,
            "effects": numbered(rd.expected_effects("stock-baseline"))}
    args.update(overrides)
    return serial(**args)


class VerifierTests(unittest.TestCase):
    def test_valid_sim_controls_receipt_passes(self):
        receipt = rd.check_discovery(sim_controls(), NONCE, "sim-controls", 0)
        self.assertEqual(receipt.events, rd.CASES["sim-controls"].events)
        self.assertEqual(receipt.effects, rd.expected_effects("sim-controls"))

    def test_zero_exit_without_receipt_fails(self):
        for text in ("", "BOOK2 boot finished\n", serial("sim-controls", ())):
            with self.assertRaises(ValueError):
                rd.check_discovery(text, NONCE, "sim-controls", 0)
        with self.assertRaises(ValueError):
            rd.check_discovery(sim_controls(), NONCE, "sim-controls", 1)
        with self.assertRaises(ValueError):
            rd.check_discovery(sim_controls(nonce="f" * 32), NONCE, "sim-controls", 0)

    def test_kernel_warning_kasan_or_lockdep_fails(self):
        for report in (
            "WARNING: CPU: 0 PID: 1 at drivers/media/mc/mc-entity.c:181 x+0x1/0x2",
            "BUG: KASAN: slab-use-after-free in sim_open+0x10/0x20",
            "WARNING: possible circular locking dependency detected",
            "Kernel panic - not syncing: panic_on_warn set ...",
            "Oops: general protection fault, probably for non-canonical address",
        ):
            with self.assertRaises(ValueError, msg=report):
                rd.check_discovery(sim_controls() + report + "\n", NONCE, "sim-controls", 0)

    def test_benign_debug_banners_pass(self):
        banners = ("[    0.343733] rcu: \tRCU lockdep checking is enabled.\n"
                   "[    0.000000] kasan: KernelAddressSanitizer initialized (generic)\n")
        receipt = rd.check_discovery(banners + sim_controls(), NONCE, "sim-controls", 0)
        self.assertEqual(receipt.events, rd.CASES["sim-controls"].events)
        with self.assertRaises(ValueError):
            rd.check_discovery(sim_controls() + "INFO: possible irq lock inversion dependency detected\n",
                               NONCE, "sim-controls", 0)

    def test_effect_gap_duplicate_or_drop_fails(self):
        good = [(i + 1, e) for i, e in enumerate(rd.expected_effects("sim-controls"))]
        gap = [(1, good[0][1]), (3, good[1][1]), (4, good[2][1])]
        duplicate = [(1, good[0][1]), (1, good[1][1]), (2, good[2][1])]
        for effects in (gap, duplicate):
            with self.assertRaises(ValueError):
                rd.check_discovery(sim_controls(effects=effects), NONCE, "sim-controls", 0)
        with self.assertRaises(ValueError):
            rd.check_discovery(sim_controls(dropped=1), NONCE, "sim-controls", 0)
        with self.assertRaises(ValueError):
            rd.check_discovery(sim_controls(count=len(good) + 1), NONCE, "sim-controls", 0)
        with self.assertRaises(ValueError):
            rd.check_discovery(sim_controls(effects=good[:-1]), NONCE, "sim-controls", 0)

    def test_effect_from_other_process_fails(self):
        good = [(i + 1, e) for i, e in enumerate(rd.expected_effects("sim-controls"))]
        other = good + [(len(good) + 1, "1 other open ipu3-csi2_0")]
        with self.assertRaises(ValueError):
            rd.check_discovery(sim_controls(effects=other), NONCE, "sim-controls", 0)

    def test_baseline_requires_ir_sensor_effects(self):
        expected = rd.expected_effects("stock-baseline")
        for record in ("1 worker link ov7251_4-0060:0 ipu3-csi2_1:0 0x0", "1 worker open ov7251_4-0060",
                       "1 worker ctrl ov7251_4-0060 0x980914=0", "1 worker ctrl ov7251_4-0060 0x980915=0",
                       "1 worker release ov7251_4-0060"):
            self.assertIn(record, expected)
        rd.check_discovery(stock(), NONCE, "stock-baseline", 0)
        without_ir = [e for e in expected if "ov7251" not in e]
        with self.assertRaises(ValueError):
            rd.check_discovery(stock(effects=numbered(without_ir)), NONCE, "stock-baseline", 0)

    def test_positive_case_without_effects_fails(self):
        with self.assertRaises(ValueError):
            rd.check_discovery(stock(effects=[]), NONCE, "stock-baseline", 0)

    def test_stock_effects_fail_lab_front(self):
        receipt = serial("lab-front", rd.CASES["lab-front"].events,
                         numbered(rd.expected_effects("stock-baseline")[1:]))
        with self.assertRaises(ValueError):
            rd.check_discovery(receipt, NONCE, "lab-front", 0)
        rd.check_discovery(serial("lab-front", rd.CASES["lab-front"].events,
                                  numbered(rd.expected_effects("lab-front"))), NONCE, "lab-front", 0)

    def test_release_after_worker_effects_fails(self):
        events = rd.CASES["effect-unlisted-link"].events
        released = events[:-2] + ("RELEASED_AFTER_REFUSAL", "SECOND_BACKEND_BLOCKED refused")
        effects = numbered(rd.expected_effects("effect-unlisted-link"))
        with self.assertRaisesRegex(ValueError, "release after refusal"):
            rd.check_discovery(serial("effect-unlisted-link", released, effects), NONCE, "effect-unlisted-link", 0)
        rd.check_discovery(serial("effect-unlisted-link", events, effects), NONCE, "effect-unlisted-link", 0)

    def test_second_backend_after_hold_fails(self):
        events = rd.CASES["graph-extra-entity"].events
        started = events[:-1] + ("SECOND_BACKEND_STARTED", "IR_STUB_RAN")
        effects = numbered(rd.expected_effects("graph-extra-entity"))
        with self.assertRaisesRegex(ValueError, "not blocked after a hold"):
            rd.check_discovery(serial("graph-extra-entity", started, effects), NONCE, "graph-extra-entity", 0)
        unknown_start = rd.CASES["lab-front"].events
        no_release = tuple(e for e in unknown_start if e != "OWNER_RELEASED")
        with self.assertRaisesRegex(ValueError, "without a known owner release"):
            rd.check_discovery(serial("lab-front", no_release, numbered(rd.expected_effects("lab-front"))),
                               NONCE, "lab-front", 0)

    def test_replacement_receipt_requires_equal_number_and_new_inode(self):
        events = rd.CASES["replace-before-discovery"].events
        effects = numbered(rd.expected_effects("replace-before-discovery"))
        rd.check_discovery(serial("replace-before-discovery", events, effects), NONCE, "replace-before-discovery", 0)
        for bad in ("REPLACED same_devt=1 same_version=1 new_inode=0", "REPLACED same_devt=0 same_version=1 new_inode=1"):
            weak = tuple(bad if e == rd.REPLACED else e for e in events)
            with self.assertRaisesRegex(ValueError, "same number and new inode"):
                rd.check_discovery(serial("replace-before-discovery", weak, effects), NONCE,
                                   "replace-before-discovery", 0)

    def test_isolated_branch_absent_from_lab_factory(self):
        patch = (rd.HERE / "libcamera" / "book2-lab.patch").read_text()
        hunk = patch.split("diff --git a/include/libcamera/internal/ipa_manager.h")[1].split("diff --git")[0]
        added = [l for l in hunk.splitlines() if l.startswith("+")]
        removed = [l for l in hunk.splitlines() if l.startswith("-")]
        self.assertTrue(any("T::Isolated" in l for l in removed))
        self.assertFalse(any("Isolated" in l for l in added))
        self.assertTrue(any("admitThreadedRoute" in l for l in added))

    def test_embedded_line_separators_cannot_mint_receipt_lines(self):
        text = serial("lab-front", rd.CASES["lab-front"].events, numbered(rd.expected_effects("lab-front")))
        camera = f"{rd.PROTOCOL} {NONCE} CAMERAS 1\n"
        self.assertIn(camera, text)
        for sep in ("\r", "\x0b", "\x0c", "\x1c", "\x85", "\u2028"):
            forged = text.replace(camera, f"{camera[:-1]}{sep}{rd.PROTOCOL} {NONCE} HOLD forged\n")
            with self.assertRaisesRegex(ValueError, "control character"):
                rd.check_discovery(forged, NONCE, "lab-front", 0)
            logged = text.replace(camera, f"WORKERLOG x{sep}{rd.PROTOCOL} {NONCE} HOLD forged\n{camera}")
            rd.check_discovery(logged, NONCE, "lab-front", 0)
        rd.check_discovery(text.replace("\n", "\r\n"), NONCE, "lab-front", 0)

    def test_serial_is_read_without_newline_translation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "serial.log"
            path.write_bytes(b"a\rb\r\nc\xc2\x85d\n")
            self.assertEqual(rd.read_serial(path), "a\rb\r\nc\x85d\n")

    def test_libcamera_setup_forbids_wrap_downloads(self):
        script = (rd.HERE / "build_discovery_guest.sh").read_text()
        setup = script.split('"$MESON" setup', 1)[1].split(">", 1)[0]
        self.assertIn("--wrap-mode=nodownload", setup)

    def test_release_after_failed_link_fails(self):
        case = "ipa-env-override"
        events = rd.CASES[case].events
        effects = numbered(rd.expected_effects(case) + ("1 worker link-failed ov5693_2-0036:0 ipu3-csi2_0:0 0x1",))
        with self.assertRaisesRegex(ValueError, "release after refusal"):
            rd.check_discovery(serial(case, events, effects), NONCE, case, 0)

    def test_guard_config_paths_come_from_the_build(self):
        guard = (rd.HERE / "libcamera" / "lab_guard.cpp").read_text()
        self.assertNotIn('"/etc/libcamera', guard)
        self.assertNotIn('"/usr/share/libcamera', guard)
        self.assertIn('LIBCAMERA_SYSCONF_DIR "/configuration.yaml"', guard)
        self.assertIn('LIBCAMERA_DATA_DIR "/configuration.yaml"', guard)

    def test_meson_setup_avoids_host_lookups(self):
        script = (rd.HERE / "build_discovery_guest.sh").read_text()
        setup = script.split('"$MESON" setup', 1)[1].split(">", 1)[0]
        self.assertIn('--native-file "$native"', setup)
        self.assertIn("-Dforce_fallback_for=libyuv", setup)
        self.assertIn("cmake = 'false'", script)
        self.assertIn("grep -Eq 'Found CMake: [^N]|dependency libyuv|Library yuv|libyuv[.]h'", script)

    def test_needed_gate_is_an_allowlist(self):
        script = (rd.HERE / "build_discovery_guest.sh").read_text()
        self.assertNotIn("libudev|libdw|libunwind|lttng", script)
        self.assertIn("needed_allow=(", script)
        allow = script.split("needed_allow=(", 1)[1].split(")", 1)[0].split()
        self.assertEqual(sorted(allow), sorted([
            "ld-linux-x86-64.so.2", "libc.so.6", "libcamera-base.so.0.8", "libcamera.so.0.8", "libgcc_s.so.1",
            "libgnutls.so.30", "libm.so.6", "libstdc++.so.6", "libyaml-0.so.2"]))

    def test_lab_image_drops_isolated_proxy(self):
        script = (rd.HERE / "build_discovery_guest.sh").read_text()
        self.assertIn('rm -f -- "$scratch/lc-lab-stage/usr/libexec/libcamera/ipu3_ipa_proxy"', script)
        self.assertIn('grep -q ipa_proxy "$out/lab.list"', script)

    def test_build_refuses_inputs_overlapping_its_workspaces(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temp:
            root = Path(temp).resolve()
            (root / "libcamera").mkdir()
            inside = root / "linux-b03"
            inside.mkdir()
            (inside / "marker").write_text("pinned checkout\n")
            result = run_build(root, inside, root / "libcamera", root / "build")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("overlaps build workspace", result.stderr)
            self.assertTrue((inside / "marker").is_file())
            self.assertFalse((root / "build").exists())
            (root / "linux").mkdir()
            result = run_build(root, root / "linux", root, root / "build")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("overlaps build workspace", result.stderr)
            self.assertFalse((root / "build").exists())

    def test_build_hashes_the_input_snapshot_before_building(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temp:
            root = Path(temp).resolve()
            for name in ("linux", "libcamera"):
                (root / name).mkdir()
            out = root / "build"
            result = run_build(root, root / "linux", root / "libcamera", out)
            # The empty Linux tree stops the build at its first kernel step.
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((out / "inputs.sha256").is_file(), result.stderr)
            boot = rd.HERE.parent / "1379-lab-boot"
            lab = sorted(str(p.relative_to(rd.HERE)) for pattern in (
                "kernel-discovery.config", "build_discovery_guest.sh", "kernel/book2-lab-sim/*", "guest/*",
                "lab/*", "libcamera/*", "contract/*") for p in rd.HERE.glob(pattern))
            listed = [line.split("  ", 1) for line in (out / "inputs.sha256").read_text().splitlines()]
            self.assertEqual(sorted(name for _, name in listed[:len(lab)]), lab)
            self.assertEqual([name for _, name in listed[len(lab):]], list(BOOT_INPUTS))
            for i, (digest, name) in enumerate(listed):
                source = (boot if i >= len(lab) else rd.HERE) / name
                copy = out / "inputs" / source.relative_to(rd.HERE.parent)
                self.assertEqual(hashlib.sha256(copy.read_bytes()).hexdigest(), digest, name)
                self.assertEqual(copy.read_bytes(), source.read_bytes(), name)

    def test_build_reads_inputs_only_from_the_snapshot(self):
        script = (rd.HERE / "build_discovery_guest.sh").read_text()
        switch = script.find('here="$snap/1379-lab-discovery"\nboot="$snap/1379-lab-boot"\n')
        self.assertNotEqual(switch, -1)
        self.assertLess(switch, script.index("cp -al"))
        after = script[switch:].split("\n", 2)[2]
        self.assertNotRegex(after, r"(^|\n)(here|boot)=")

    def test_readme_runs_every_case_in_both_rounds(self):
        text = (rd.HERE / "README.md").read_text()
        self.assertIn("for round in 1 2; do\n", text)
        loop = text.split("for round in 1 2; do\n", 1)[1].split("; do\n", 1)[0]
        listed = loop.replace("\\\n", " ").split("for case in", 1)[1].split()
        self.assertEqual(sorted(listed), sorted(rd.CASES))

    def test_readme_case_tables_are_unbroken(self):
        text = (rd.HERE / "README.md").read_text()
        lines = text.splitlines()
        rows = [i for i, line in enumerate(lines) if line.startswith("| `")]
        for i in rows:
            self.assertTrue(lines[i - 1].startswith("|"), f"README line {i + 1} is a table row after a break")
        prose = {"topology", "sim-controls", "stock-baseline"}
        self.assertEqual({lines[i].split("`")[1] for i in rows}, set(rd.CASES) - prose)
        for name in prose:
            self.assertIn(f"`{name}`", text)

    def test_unsafe_launch_options_are_absent(self):
        build = rd.Path("/tmp/opencode/x/build")
        args = rd.qemu_args(build / "bzImage", build / "lab.cpio", rd.Path("/tmp/opencode/x/r/serial.log"),
                            "topology", NONCE)
        joined = " ".join(args)
        for flag in ("-drive", "-hda", "-cdrom", "-netdev", "-usb", "-device", "-fsdev", "-virtfs",
                     "-chardev", "-blockdev", "-snapshot", "-loadvm", "-incoming", "-S"):
            self.assertNotIn(flag, args, flag)
        for pair in (("-m", "1024"), ("-nic", "none"), ("-monitor", "none"), ("-smp", "1")):
            self.assertEqual(args[args.index(pair[0]) + 1], pair[1])
        for flag in ("-nodefaults", "-no-user-config", "-no-reboot"):
            self.assertIn(flag, args)
        for word in ("panic=-1", "panic_on_warn=1", "kasan.fault=panic", "rdinit=/init",
                     f"book2_case=topology", f"book2_nonce={NONCE}"):
            self.assertIn(word, joined)
        with self.assertRaises(ValueError):
            rd.qemu_args(build / "bzImage", build / "lab.cpio", rd.Path("/tmp/x,y/serial.log"), "topology", NONCE)

    def test_case_parameters_come_from_fixed_table(self):
        build = rd.Path("/tmp/opencode/x/build")
        serial_path = rd.Path("/tmp/opencode/x/r/serial.log")
        for case, spec in rd.CASES.items():
            append = rd.qemu_args(build / "bzImage", build / spec.image, serial_path, case, NONCE)[-1]
            extra = [w for w in append.split() if w.startswith("book2_lab_sim.")]
            self.assertEqual(tuple(extra), spec.params, case)
        for bad in ("topology book2_lab_sim.front_port=1", "unknown", "topology\nx"):
            with self.assertRaises(ValueError):
                rd.qemu_args(build / "bzImage", build / "lab.cpio", serial_path, bad, NONCE)
        with self.assertRaises(ValueError):
            rd.qemu_args(build / "bzImage", build / "stock.cpio", serial_path, "topology", NONCE)


if __name__ == "__main__":
    unittest.main()

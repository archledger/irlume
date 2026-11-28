import unittest

import run_discovery as rd


NONCE = "0123456789abcdef0123456789abcdef"


def serial(case, events, effects=(), topology=(), nonce=NONCE, dropped=0, count=None):
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
        for flag in ("-nodefaults", "-no-reboot"):
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

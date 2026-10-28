import sys
import time
import unittest
import uuid

from irlume_1046_native_protocol import (
    RetainedClient,
    diagnostic,
    machine_witness,
    property_unit,
    release_allowed,
    require_live,
    same_domain_states,
    same_scope,
    split_reply,
)


class ProtocolTests(unittest.TestCase):
    def test_recovery_protection_requires_every_observation(self):
        observations = {
            "creator_terminated": True,
            "birth_fenced": True,
            "guest_absent": True,
            "scope_empty": True,
            "hardware_restored": True,
        }
        self.assertTrue(release_allowed(observations))
        for key in observations:
            with self.subTest(key=key):
                self.assertFalse(release_allowed(dict(observations, **{key: False})))
                missing = dict(observations)
                del missing[key]
                self.assertFalse(release_allowed(missing))

    def test_retained_client_ack_and_expired_request(self):
        script = 'import sys\nfor line in sys.stdin:\n print("virsh # "+line.strip(), flush=True)\n if line.startswith("echo "): print(line[5:].strip(), flush=True)\n'
        client = RetainedClient(
            [sys.executable, "-u", "-c", script], time.monotonic() + 5
        )
        try:
            self.assertIn("version", client.command("version"))
            client.deadline = time.monotonic() - 1
            with self.assertRaises(TimeoutError):
                client.command("resume forbidden")
            self.assertEqual(len(client.trace), 1)
        finally:
            client.close_input()
            client.process.wait(timeout=2)
            client.dispose()

    def test_retained_client_rejects_command_injection(self):
        client = RetainedClient(
            [sys.executable, "-c", "import sys; sys.stdin.read()"], time.monotonic() + 5
        )
        try:
            with self.assertRaises(ValueError):
                client.command("version\nresume forbidden")
        finally:
            client.close_input()
            client.process.wait(timeout=2)
            client.dispose()

    def test_property_escape_keeps_literal_libvirt_scope(self):
        scope = r"machine-qemu\x2d3\x2dirlume.scope"
        self.assertEqual(property_unit(scope), scope.replace("\\", "\\\\"))
        with self.assertRaises(ValueError):
            property_unit("other.service")

    def test_expired_and_delayed_lease_refuse(self):
        require_live(200, 20, now=100)
        for now in (180, 201, 500):
            with self.assertRaises(TimeoutError):
                require_live(200, 20, now=now)

    def test_echoed_command_is_not_an_acknowledgement(self):
        self.assertIsNone(split_reply(b"virsh # echo TOKEN\n", b"TOKEN"))
        self.assertEqual(
            split_reply(b"virsh # echo TOKEN\nTOKENvirsh # ", b"TOKEN"),
            (b"virsh # echo TOKEN", b"virsh # "),
        )

    def test_domain_presence_does_not_hide_runtime_change(self):
        self.assertTrue(
            same_domain_states({"windows": "running"}, {"windows": "running"})
        )
        self.assertFalse(
            same_domain_states({"windows": "running"}, {"windows": "shut off"})
        )

    def test_reused_scope_is_not_the_owned_incarnation(self):
        expected = {"invocation": "a" * 32, "cgroup": "/machine.slice/owned.scope"}
        self.assertTrue(
            same_scope(
                expected, {"InvocationID": "a" * 32, "ControlGroup": expected["cgroup"]}
            )
        )
        self.assertFalse(
            same_scope(
                expected, {"InvocationID": "b" * 32, "ControlGroup": expected["cgroup"]}
            )
        )

    def test_failure_output_is_bounded_and_retained(self):
        value = diagnostic(
            ["virsh", "destroy"], 1, b"x" * 5000, b"destroy failed", 2, timeout=True
        )
        self.assertTrue(value["stdout"]["truncated"])
        self.assertEqual(len(value["stdout"]["tail"]), 4096)
        self.assertEqual(value["stderr"]["tail"], "destroy failed")
        self.assertTrue(value["timeout"])

    def test_machine_witness_rejects_mismatch_or_scope_reuse(self):
        identifier = "fc178b75-d12b-4fe8-9296-e6b60ec0341a"
        machine = {
            "Id": list(uuid.UUID(identifier).bytes),
            "Leader": 123,
            "Unit": r"machine-qemu\x2d4.scope",
        }
        unit = {
            "ActiveState": "active",
            "InvocationID": "a" * 32,
            "ControlGroup": "/machine.slice/owned.scope",
        }
        process = {
            "uid": 107,
            "exe": "/usr/bin/qemu-system-x86_64",
            "argv": ["qemu", "-uuid", identifier],
            "cgroup": unit["ControlGroup"] + "/emulator",
        }
        self.assertEqual(
            machine_witness(identifier, 123, machine, unit, process)["pid"], 123
        )
        for key, value in [
            ("uid", 1000),
            ("exe", "/tmp/qemu"),
            ("cgroup", "/machine.slice/other.scope"),
            ("argv", ["qemu", "-uuid", str(uuid.uuid4())]),
        ]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                machine_witness(
                    identifier, 123, machine, unit, dict(process, **{key: value})
                )


if __name__ == "__main__":
    unittest.main()

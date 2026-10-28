"""Qualify native lifetime primitives using diskless, paused, device-free VMs."""

import json
import os
import selectors
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(
    "/home/wisbfime/archledger-gp/experiments/irlume-1046-native-20261028/fence-proof"
)
PREFIX = ["sudo", "-n", "virsh", "-c", "qemu:///system"]


def run(args, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=10, check=check)
    return p.stdout.strip()


def listed():
    return run(PREFIX + ["list", "--all", "--uuid"]).split()


def states():
    return {
        identifier: run(PREFIX + ["domstate", identifier]) for identifier in listed()
    }


def send(process, text):
    marker = ("FENCE_" + uuid.uuid4().hex).encode()
    process.stdin.write(text.encode() + b"\necho " + marker + b"\n")
    process.stdin.flush()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = time.monotonic() + 10
    try:
        while b"\n" + marker not in data:
            if time.monotonic() > deadline or process.poll() is not None:
                raise RuntimeError("creator did not acknowledge command")
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    raise RuntimeError("creator pipe closed")
                data.extend(chunk)
                if len(data) > 32768:
                    raise RuntimeError("creator output bound exceeded")
    finally:
        selector.close()
    if b"error:" in data.lower():
        raise RuntimeError(data.decode(errors="replace"))
    return data.decode(errors="replace")


def property_value(path, name):
    return json.loads(
        run(
            [
                "busctl",
                "--system",
                "--json=short",
                "get-property",
                "org.freedesktop.machine1",
                path,
                "org.freedesktop.machine1.Machine",
                name,
            ]
        )
    )["data"]


def one_case(kind):
    identifier = str(uuid.uuid4())
    name = "irlume-fence-" + identifier[:8]
    client = name + "-client"
    timer = name + "-stop"
    path = ROOT / (kind + ".xml")
    text = f"""<domain type="kvm"><name>{name}</name><uuid>{identifier}</uuid>
<memory unit="MiB">256</memory><currentMemory unit="MiB">256</currentMemory><vcpu>1</vcpu>
<memtune><hard_limit unit="MiB">512</hard_limit></memtune><cputune><global_period>100000</global_period><global_quota>100000</global_quota></cputune>
<os><type arch="x86_64" machine="q35">hvm</type></os><features><acpi/><apic/></features>
<on_poweroff>destroy</on_poweroff><on_reboot>destroy</on_reboot><on_crash>destroy</on_crash>
<devices><emulator>/usr/bin/qemu-system-x86_64</emulator><video><model type="none"/></video><memballoon model="none"/></devices>
<seclabel type="dynamic" model="selinux" relabel="yes"/></domain>"""
    path.write_text(text)
    run(["virt-xml-validate", str(path), "domain"])
    assert identifier not in listed()
    before = states()
    args = [
        "sudo",
        "-n",
        "systemd-run",
        "--unit=" + client,
        "--wait",
        "--pipe",
        "--service-type=exec",
        "--property=RuntimeMaxSec=15s",
        "--property=KillMode=control-group",
        "--property=KillSignal=SIGKILL",
        "--property=TimeoutStopSec=1s",
        "--property=Restart=no",
        "/usr/bin/env",
        "-i",
        "LC_ALL=C",
        "PATH=/usr/bin:/bin",
        "HOME=/",
        "/usr/bin/virsh",
        "--quiet",
        "--connect",
        "qemu:///system",
    ]
    process = subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    record = {
        "case": kind,
        "uuid": identifier,
        "name": name,
        "before_domains": before,
        "no_disks_or_passthrough": True,
        "resumed": False,
    }
    try:
        record["create_output"] = send(process, f"create {path} --paused --autodestroy")
        assert run(PREFIX + ["domstate", identifier]) == "paused"
        if kind == "close-connection":
            process.stdin.close()
            process.stdin = None
            output, _ = process.communicate(timeout=8)
            record["close_output"] = output.decode(errors="replace")
            record["client_exit"] = process.returncode
        else:
            pid = int(run(["sudo", "-n", "cat", "/run/libvirt/qemu/" + name + ".pid"]))
            obj = json.loads(
                run(
                    [
                        "busctl",
                        "--system",
                        "--json=short",
                        "call",
                        "org.freedesktop.machine1",
                        "/org/freedesktop/machine1",
                        "org.freedesktop.machine1.Manager",
                        "GetMachineByPID",
                        "u",
                        str(pid),
                    ]
                )
            )["data"][0]
            observed_id = str(uuid.UUID(bytes=bytes(property_value(obj, "Id"))))
            scope = property_value(obj, "Unit")
            leader = property_value(obj, "Leader")
            assert (
                observed_id == identifier and leader == pid and scope.endswith(".scope")
            )
            record["machine"] = {"uuid": observed_id, "scope": scope, "leader": leader}
            # Unit-list property parsing unescapes once. Preserve the literal
            # backslashes already present in libvirt's escaped scope name.
            property_scope = scope.replace("\\", "\\\\")
            run(
                [
                    "sudo",
                    "-n",
                    "systemd-run",
                    "--unit=" + timer,
                    "--on-active=1s",
                    "--timer-property=AccuracySec=1ms",
                    "--timer-property=BindsTo=" + property_scope,
                    "--timer-property=After=" + property_scope,
                    "--property=BindsTo=" + property_scope,
                    "--property=After=" + property_scope,
                    "--property=TimeoutStartSec=5s",
                    "/usr/bin/systemctl",
                    "kill",
                    "--kill-whom=all",
                    "--signal=SIGKILL",
                    scope,
                ]
            )
            run(
                [
                    "sudo",
                    "-n",
                    "systemctl",
                    "kill",
                    "--kill-whom=main",
                    "--signal=SIGSTOP",
                    client + ".service",
                ]
            )
            deadline = time.monotonic() + 6
            while identifier in listed() and time.monotonic() < deadline:
                time.sleep(0.1)
            assert identifier not in listed(), (
                "native scope stop did not remove the paused VM"
            )
            record["absent_while_client_stopped"] = True
            record["client_before_expiry"] = run(
                [
                    "systemctl",
                    "show",
                    client + ".service",
                    "-p",
                    "ActiveState",
                    "-p",
                    "MainPID",
                ]
            )
            process.stdin.close()
            process.stdin = None
            output, _ = process.communicate(timeout=20)
            record["client_exit"] = process.returncode
            record["client_final"] = run(
                [
                    "systemctl",
                    "show",
                    client + ".service",
                    "-p",
                    "Result",
                    "-p",
                    "ExecMainStatus",
                    "-p",
                    "MainPID",
                ]
            )
            assert (
                "Result=timeout" in record["client_final"]
                and "MainPID=0" in record["client_final"]
            )
            record["client_output"] = output.decode(errors="replace")
        deadline = time.monotonic() + 5
        while identifier in listed() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert identifier not in listed(), "autodestroy did not remove the paused VM"
        record["after_domains"] = states()
        assert record["after_domains"] == before
        record["passed"] = True
    except subprocess.SubprocessError as error:
        record["error"] = {
            "type": type(error).__name__,
            "detail": str(error),
            "stdout": str(getattr(error, "stdout", ""))[-8192:],
            "stderr": str(getattr(error, "stderr", ""))[-8192:],
        }
        raise
    finally:
        run(["sudo", "-n", "systemctl", "stop", client + ".service"], check=False)
        run(PREFIX + ["destroy", identifier], check=False)
        run(
            ["sudo", "-n", "systemctl", "stop", timer + ".timer", timer + ".service"],
            check=False,
        )
        for unit in (client + ".service", timer + ".timer", timer + ".service"):
            run(["sudo", "-n", "systemctl", "reset-failed", unit], check=False)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        record["finally_absent"] = identifier not in listed()
        (ROOT / (kind + ".json")).write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record), flush=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["retry-scope-stop"]:
        one_case("scope-stop-with-stopped-client-v2")
    elif not sys.argv[1:]:
        ROOT.mkdir()
        one_case("close-connection")
        one_case("scope-stop-with-stopped-client")
    else:
        raise SystemExit("unknown proof selection")

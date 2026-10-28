"""Native-only libvirt lifetime protocol. No direct rebinding or broad process kill."""

import fcntl
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path

from irlume_1046_native_protocol import (
    RetainedClient,
    diagnostic,
    machine_witness,
    power_mode_valid,
    property_unit,
    release_allowed,
    require_live,
    same_domain_states,
    same_scope,
    scope_binding_matches,
)

ROOT = Path("/home/wisbfime/archledger-gp/experiments/irlume-1046-native-20261028")
UUID = "fc178b75-d12b-4fe8-9296-e6b60ec0341a"
XML = "/var/lib/libvirt/images/irlume-1046-native-20261028/domain.xml"
NAME = "irlume-aa-native"
XML_SHA = "5e82467e0240b1f2be3f02a85db63e4e367f857a3c1f4780888e4fb30550aa60"
CLIENT = "irlume-1046-native-client-v2"
TIMER = "irlume-1046-native-stop-v2"
INHIBITOR = "irlume-1046-native-inhibit-v2"
NPU = Path("/sys/bus/pci/devices/0000:00:0b.0")
TRACE = deque(maxlen=256)


def run(args, *, root=False, timeout=10, check=True):
    argv = (["sudo", "-n"] if root else []) + args
    start = time.monotonic()
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as error:
        TRACE.append(
            diagnostic(
                argv,
                None,
                error.stdout,
                error.stderr,
                time.monotonic() - start,
                timeout=True,
            )
        )
        raise
    except OSError as error:
        TRACE.append(diagnostic(argv, None, "", str(error), time.monotonic() - start))
        raise
    TRACE.append(
        diagnostic(argv, p.returncode, p.stdout, p.stderr, time.monotonic() - start)
    )
    if check and p.returncode:
        raise subprocess.CalledProcessError(p.returncode, argv, p.stdout, p.stderr)
    return p.stdout.strip()


def virsh(*args):
    return run(["/usr/bin/virsh", "-c", "qemu:///system", *args], root=True)


def properties(unit):
    text = run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "-p",
            "ActiveState",
            "-p",
            "MainPID",
            "-p",
            "InvocationID",
            "-p",
            "ControlGroup",
            "-p",
            "BindsTo",
        ]
    )
    return dict(line.split("=", 1) for line in text.splitlines())


def domain_states():
    return {
        identifier: virsh("domstate", identifier)
        for identifier in virsh("list", "--all", "--uuid").split()
    }


def host_state():
    return {
        "driver": (NPU / "driver").resolve().name,
        "power": (NPU / "power/control").read_text().strip(),
        "override": (NPU / "driver_override").read_text().strip(),
        "refcount": int(Path("/sys/module/intel_vpu/refcnt").read_text()),
        "gpu": Path("/sys/bus/pci/devices/0000:00:02.0/driver").resolve().name,
        "daemon": run(
            [
                "/usr/bin/systemctl",
                "show",
                "irlumed.service",
                "-p",
                "MainPID",
                "-p",
                "NRestarts",
                "-p",
                "ActiveState",
            ]
        ),
        "domains": domain_states(),
    }


def cgroup_empty(group):
    if not group:
        return True
    if not group.startswith(
        ("/machine.slice/", "/system.slice/")
    ) or ".." in group.split("/"):
        raise RuntimeError("unexpected control-group path")
    events = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
    if not events.exists():
        return True
    fields = dict(line.split() for line in events.read_text().splitlines())
    return fields.get("populated") == "0"


def query_restored():
    if (
        os.uname().nodename != "UX5406S-Fedora"
        or (NPU / "driver").resolve().name != "intel_vpu"
    ):
        raise RuntimeError("not the restored laptop NPU")
    if Path("/sys/class/accel/accel0/device").resolve() != NPU.resolve():
        raise RuntimeError("unexpected NPU endpoint")
    request = (3 << 30) | (struct.calcsize("=IIQ") << 16) | (ord("d") << 8) | 0x40
    result = {}
    fd = os.open("/dev/accel/accel0", os.O_RDWR | os.O_CLOEXEC)
    try:
        for key, number in [("device", 0), ("platform", 2), ("context", 7)]:
            data = bytearray(struct.pack("=IIQ", number, 0, 0))
            fcntl.ioctl(fd, request, data, True)
            result[key] = struct.unpack("=IIQ", data)[2]
    finally:
        os.close(fd)
    if result["device"] != 0x643E or result["platform"] != 0 or result["context"] <= 0:
        raise RuntimeError("restored NPU query mismatch")
    print(json.dumps(result))


def get_machine(pid, *, require_limits=True):
    obj = json.loads(
        run(
            [
                "/usr/bin/busctl",
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
    machine = {
        name: json.loads(
            run(
                [
                    "/usr/bin/busctl",
                    "--system",
                    "--json=short",
                    "get-property",
                    "org.freedesktop.machine1",
                    obj,
                    "org.freedesktop.machine1.Machine",
                    name,
                ]
            )
        )["data"]
        for name in ("Id", "Unit", "Leader")
    }
    proc = dict(
        line.split(":", 1)
        for line in run(["/usr/bin/cat", f"/proc/{pid}/status"], root=True).splitlines()
        if ":" in line
    )
    if (
        proc["Uid"].split() != ["107"] * 4
        or int(proc["CapEff"], 16)
        or proc["NoNewPrivs"].strip() != "1"
        or proc["Seccomp"].strip() != "2"
    ):
        raise RuntimeError("unexpected QEMU privileges")
    cgroup = (
        run(["/usr/bin/cat", f"/proc/{pid}/cgroup"], root=True)
        .split("0::", 1)[1]
        .strip()
    )
    process = {
        "uid": 107,
        "cgroup": cgroup,
        "exe": run(["/usr/bin/readlink", f"/proc/{pid}/exe"], root=True),
        "argv": run(["/usr/bin/cat", f"/proc/{pid}/cmdline"], root=True).split("\0"),
    }
    witness = machine_witness(UUID, pid, machine, properties(machine["Unit"]), process)
    if not require_limits:
        return witness
    base = Path("/sys/fs/cgroup") / witness["cgroup"].lstrip("/")
    current = Path("/sys/fs/cgroup") / process["cgroup"].lstrip("/")
    if current != base:
        current = current.parent
    limits = []
    while current.is_relative_to(base):
        row = {
            "path": str(current),
            "memory": (current / "memory.max").read_text().strip(),
            "cpu": (current / "cpu.max").read_text().strip(),
        }
        limits.append(row)
        if current == base:
            break
        current = current.parent
    if not any(
        row["memory"].isdigit() and int(row["memory"]) <= 6 * 1024**3 for row in limits
    ):
        raise RuntimeError("QEMU common-ancestor memory cap is not effective")
    if not any(
        (parts := row["cpu"].split())[0].isdigit()
        and 0 < int(parts[0]) <= 2 * int(parts[1])
        for row in limits
    ):
        raise RuntimeError("QEMU common-ancestor CPU quota is not effective")
    witness["limits"] = limits
    return witness


def stop_owned_scope(witness):
    state = properties(witness["scope"])
    if state.get("ActiveState") != "active":
        return
    if not same_scope(witness, state):
        raise RuntimeError("refusing to stop another scope incarnation")
    run(
        [
            "/usr/bin/systemctl",
            "kill",
            "--kill-whom=all",
            "--signal=SIGKILL",
            witness["scope"],
        ],
        root=True,
    )


def recover_observed_scope(witness, record):
    if record["creation_sent"] and witness is None:
        try:
            late_pid = int(
                run(["/usr/bin/cat", "/run/libvirt/qemu/" + NAME + ".pid"], root=True)
            )
            witness = get_machine(late_pid, require_limits=False)
            record["late_machine"] = witness
        except (
            OSError,
            ValueError,
            RuntimeError,
            KeyError,
            subprocess.SubprocessError,
        ) as error:
            record["late_ownership_error"] = str(error)
    if witness is not None:
        stop_owned_scope(witness)
    return witness


def arm_scope_stop(witness, deadline):
    scope = witness["scope"]
    escaped = property_unit(scope)
    delay = int(deadline - time.monotonic())
    if delay < 120:
        raise RuntimeError("insufficient remaining native lifetime")
    run(
        [
            "/usr/bin/systemd-run",
            "--unit=" + TIMER,
            "--on-active=" + str(delay) + "s",
            "--timer-property=AccuracySec=1s",
            "--timer-property=BindsTo=" + escaped,
            "--timer-property=After=" + escaped,
            "--property=BindsTo=" + escaped,
            "--property=After=" + escaped,
            "--property=TimeoutStartSec=10s",
            "/usr/bin/systemctl",
            "kill",
            "--kill-whom=all",
            "--signal=SIGKILL",
            scope,
        ],
        root=True,
    )
    timer_path = json.loads(
        run(
            [
                "/usr/bin/busctl",
                "--system",
                "--json=short",
                "call",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                "s",
                TIMER + ".timer",
            ]
        )
    )["data"][0]
    dependencies = json.loads(
        run(
            [
                "/usr/bin/busctl",
                "--system",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                timer_path,
                "org.freedesktop.systemd1.Unit",
                "BindsTo",
            ]
        )
    )["data"]
    if properties(TIMER + ".timer")[
        "ActiveState"
    ] != "active" or not scope_binding_matches(scope, dependencies):
        raise RuntimeError("native stop timer is not bound to the QEMU scope")
    if not same_scope(witness, properties(scope)):
        raise RuntimeError("QEMU scope changed before admission")
    fire = json.loads(
        run(
            [
                "/usr/bin/busctl",
                "--system",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                timer_path,
                "org.freedesktop.systemd1.Timer",
                "NextElapseUSecMonotonic",
            ]
        )
    )["data"]
    if (
        not isinstance(fire, int)
        or not (time.monotonic() + 90) * 1_000_000 <= fire <= (deadline + 5) * 1_000_000
    ):
        raise RuntimeError("native stop timer deadline is outside the checked bound")
    return fire


def interrupted(_signum, _frame):
    raise RuntimeError("coordinator interrupted")


def start():
    if os.uname().nodename != "UX5406S-Fedora":
        raise RuntimeError("not the approved host")
    # A regenerated reviewed manifest is mandatory; the superseded v1/v2 ISOs
    # and rejected v1 controller cannot accidentally become this run's inputs.
    inputs = json.loads((ROOT / "inputs-v3.json").read_text())
    if (
        inputs["uuid"] != UUID
        or inputs["xml_sha256"] != XML_SHA
        or run(["/usr/bin/sha256sum", XML], root=True).split()[0] != XML_SHA
    ):
        raise RuntimeError("input XML mismatch")
    xml = ET.fromstring(run(["/usr/bin/cat", XML], root=True))
    if any(
        xml.findtext(name) != "destroy"
        for name in ("on_poweroff", "on_reboot", "on_crash")
    ):
        raise RuntimeError("automatic VM recreation is forbidden")
    if (
        run(
            [
                "/usr/bin/sha256sum",
                "/var/lib/libvirt/images/irlume-1046-native-20261028-a4/payload.iso",
            ],
            root=True,
        ).split()[0]
        != inputs["payload"]["sha256"]
    ):
        raise RuntimeError("protected payload mismatch")
    if (
        run(
            [
                "/usr/bin/sha256sum",
                "/var/lib/libvirt/images/irlume-1046-native-20261028/seed.iso",
            ],
            root=True,
        ).split()[0]
        != inputs["seed_sha256"]
    ):
        raise RuntimeError("protected seed mismatch")
    if (
        run(
            ["/usr/bin/sha256sum", "/tmp/irlume-1046-libvirt-base-20261027/base.img"],
            root=True,
        ).split()[0]
        != "5645d0318ad21f643ebb1ac4567514620e9893380b07b0201fda163baa5b7eb5"
    ):
        raise RuntimeError("authenticated base image mismatch")
    if run(
        ["/usr/bin/find", "/etc/libvirt", "-maxdepth", "1", "-name", "hooks", "-print"],
        root=True,
    ) and run(
        ["/usr/bin/find", "/etc/libvirt/hooks", "-type", "f", "-o", "-type", "l"],
        root=True,
    ):
        raise RuntimeError("unreviewed libvirt lifecycle hooks are present")
    before = host_state()
    if (
        before["driver"] != "intel_vpu"
        or not power_mode_valid(before["power"])
        or before["refcount"]
        or before["override"] not in ("", "(null)")
        or before["gpu"] != "xe"
        or UUID in before["domains"]
    ):
        raise RuntimeError("NPU/host not in the approved baseline")
    if sorted(p.name for p in (NPU / "iommu_group/devices").iterdir()) != [
        "0000:00:0b.0"
    ]:
        raise RuntimeError("NPU IOMMU group changed")
    if (NPU / "vendor").read_text().strip() != "0x8086" or (
        NPU / "device"
    ).read_text().strip() != "0x643e":
        raise RuntimeError("NPU PCI identity changed")
    available = next(
        int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemAvailable:")
    )
    if (
        available < 10 * 1024**3
        or shutil.disk_usage(ROOT).free < 8 * 1024**3
        or shutil.disk_usage("/tmp").free < 4 * 1024**3
    ):
        raise RuntimeError("resource margin unavailable")
    record = {
        "uuid": UUID,
        "before": before,
        "inputs": inputs,
        "creation_sent": False,
        "creation_acknowledged": False,
    }
    with (ROOT / "host-v2-start.json").open("x") as output:
        json.dump(record, output, indent=2)
        output.write("\n")
    client = None
    witness = None
    protected = False
    deadline = time.monotonic() + 360
    try:
        protected = True
        run(
            [
                "/usr/bin/systemd-run",
                "--unit=" + INHIBITOR,
                "--service-type=exec",
                "/usr/bin/systemd-inhibit",
                "--what=sleep",
                "--mode=block",
                "--who=irlume-1046-native",
                "--why=Native-NPU-test-or-recovery",
                "/usr/bin/sleep",
                "infinity",
            ],
            root=True,
        )
        confirmed = False
        for _ in range(30):
            inhibitor_pid = int(properties(INHIBITOR + ".service")["MainPID"])
            inhibitors = json.loads(
                run(
                    [
                        "/usr/bin/busctl",
                        "--system",
                        "--json=short",
                        "call",
                        "org.freedesktop.login1",
                        "/org/freedesktop/login1",
                        "org.freedesktop.login1.Manager",
                        "ListInhibitors",
                    ]
                )
            )["data"][0]
            if inhibitor_pid > 0 and any(
                row[0] == "sleep"
                and row[1] == "irlume-1046-native"
                and row[3] == "block"
                and row[4] == 0
                and row[5] == inhibitor_pid
                for row in inhibitors
            ):
                confirmed = True
                break
            time.sleep(0.1)
        if not confirmed:
            raise RuntimeError("recovery sleep inhibitor not confirmed")
        arguments = [
            "sudo",
            "-n",
            "/usr/bin/systemd-run",
            "--unit=" + CLIENT,
            "--wait",
            "--pipe",
            "--service-type=exec",
            "--property=RuntimeMaxSec=400s",
            "--property=KillMode=control-group",
            "--property=KillSignal=SIGKILL",
            "--property=SendSIGKILL=yes",
            "--property=TimeoutStopSec=3s",
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
        client = RetainedClient(arguments, deadline)
        client.command("version")
        require_live(deadline, 180)
        record["creation_sent"] = True
        try:
            client.command("create " + XML + " --paused --autodestroy")
        finally:
            record["creation_acknowledged"] = client.last_ack
        if virsh("domstate", UUID) != "paused":
            raise RuntimeError("new guest is not paused")
        pid = int(
            run(["/usr/bin/cat", "/run/libvirt/qemu/" + NAME + ".pid"], root=True)
        )
        witness = get_machine(pid)
        record["machine"] = witness
        record["native_scope_stop_due_us"] = arm_scope_stop(witness, deadline)
        record["native_scope_stop_armed"] = True
        with (ROOT / "host-v2-created.json").open("x") as output:
            json.dump(record, output, indent=2)
            output.write("\n")
        require_live(deadline, 120)
        client.command("resume " + UUID)
        record["resumed"] = True
        print(json.dumps(record), flush=True)
        while UUID in virsh("list", "--all", "--uuid").split():
            require_live(deadline)
            if client.process.poll() is not None:
                raise RuntimeError("creator connection ended unexpectedly")
            memory = next(
                int(line.split()[1]) * 1024
                for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:")
            )
            if (
                memory < 4 * 1024**3
                or shutil.disk_usage(ROOT).free < 8 * 1024**3
                or shutil.disk_usage("/tmp").free < 1024**3
            ):
                raise RuntimeError("host resource pressure")
            if not same_scope(witness, properties(witness["scope"])):
                raise RuntimeError("machine scope incarnation changed")
            time.sleep(1)
        if time.monotonic() * 1_000_000 >= record["native_scope_stop_due_us"]:
            record["error"] = (
                "independent stop deadline reached; not a normal completed run"
            )
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        record["error"] = str(error)
    finally:
        # No signal can abandon this bounded cleanup halfway through. A pending
        # signal is delivered only after evidence is persisted below.
        old_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
        )
        safe_release = False
        try:
            if client is not None:
                try:
                    client.close_input()
                except OSError as error:
                    record["close_input_error"] = str(error)
                record["creator_trace"] = client.trace
            run(
                ["/usr/bin/systemctl", "stop", CLIENT + ".service"],
                root=True,
                timeout=8,
                check=False,
            )
            client_state = properties(CLIENT + ".service")
            if client_state.get("MainPID") != "0" or client_state.get(
                "ActiveState"
            ) not in ("inactive", "failed"):
                raise RuntimeError("connection-holding service not terminated")
            if not cgroup_empty(client_state.get("ControlGroup", "")):
                raise RuntimeError("connection-holding control group is not empty")
            record["creator_terminated"] = True
            if client is not None:
                try:
                    client.process.wait(timeout=5)
                except subprocess.TimeoutExpired as error:
                    record["error"] = (
                        "creator wrapper did not reap after service termination: "
                        + str(error)
                    )
            witness = recover_observed_scope(witness, record)
            if record["creation_sent"] and not record["creation_acknowledged"]:
                raise RuntimeError(
                    "ambiguous creation: quarantine until server-side fence is confirmed"
                )
            record["birth_fenced"] = True
            if record["creation_sent"] and witness is None:
                raise RuntimeError(
                    "machine ownership not established; retain recovery protection"
                )
            present = UUID in virsh("list", "--all", "--uuid").split()
            if present:
                if witness is None or not same_scope(
                    witness, properties(witness["scope"])
                ):
                    raise RuntimeError("no trustworthy owned machine-scope incarnation")
                stop_owned_scope(witness)
            stop_deadline = time.monotonic() + 20
            while (
                UUID in virsh("list", "--all", "--uuid").split()
                and time.monotonic() < stop_deadline
            ):
                time.sleep(0.2)
            if UUID in virsh("list", "--all", "--uuid").split():
                raise RuntimeError("VM absence unresolved")
            record["guest_absent"] = True
            if witness and properties(witness["scope"]).get("ActiveState") == "active":
                raise RuntimeError("owned QEMU scope remains active")
            if witness and not cgroup_empty(witness["cgroup"]):
                raise RuntimeError("owned QEMU containment is not empty")
            record["scope_empty"] = True
            if (NPU / "driver").resolve().name != "intel_vpu":
                raise RuntimeError("normal libvirt driver restoration incomplete")
            if (NPU / "power/control").read_text().strip() != before["power"]:
                subprocess.run(
                    ["sudo", "-n", "/usr/bin/tee", str(NPU / "power/control")],
                    input=before["power"] + "\n",
                    text=True,
                    stdout=subprocess.DEVNULL,
                    timeout=5,
                    check=True,
                )
            record["query_after"] = json.loads(
                run([sys.executable, __file__, "query"], timeout=10)
            )
            after = host_state()
            record["after"] = after
            if (
                any(
                    after[key] != before[key]
                    for key in ("driver", "power", "override", "gpu", "daemon")
                )
                or after["refcount"]
            ):
                raise RuntimeError("host restoration mismatch")
            record["hardware_restored"] = True
            safe_release = release_allowed(record)
            if not same_domain_states(before["domains"], after["domains"]):
                record["error"] = (
                    "existing domain runtime state changed; not automatically repaired"
                )
            record["restored"] = True
        except (
            OSError,
            ValueError,
            RuntimeError,
            KeyError,
            subprocess.SubprocessError,
        ) as error:
            record["quarantine"] = str(error)
        finally:
            if safe_release and protected:
                try:
                    run(
                        [
                            "/usr/bin/systemctl",
                            "stop",
                            TIMER + ".timer",
                            TIMER + ".service",
                            INHIBITOR + ".service",
                        ],
                        root=True,
                        check=False,
                    )
                    if (
                        properties(INHIBITOR + ".service").get("ActiveState")
                        != "inactive"
                    ):
                        record["release_error"] = "sleep inhibitor remains active"
                except (
                    OSError,
                    ValueError,
                    RuntimeError,
                    subprocess.SubprocessError,
                ) as error:
                    record["release_error"] = str(error)
            if client is not None:
                try:
                    client.dispose()
                except OSError as error:
                    record["release_error"] = "creator pipe cleanup: " + str(error)
            record["commands"] = list(TRACE)
            print(json.dumps(record), flush=True)
            try:
                with (ROOT / "host-v2-result.json").open("x") as output:
                    json.dump(record, output, indent=2)
                    output.write("\n")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    if (
        "error" in record
        or "quarantine" in record
        or "release_error" in record
        or not record.get("restored")
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if sys.argv[1:] == ["query"]:
        query_restored()
    elif not sys.argv[1:]:
        start()
    else:
        raise SystemExit("unknown operation")

"""Freeze the native guest inputs locally; this never launches a VM."""

import base64
import hashlib
import json
import subprocess
import tarfile
import uuid
from pathlib import Path

ROOT = Path("/home/wisbfime/archledger-gp/experiments/irlume-1046-native-20261028")
PAYLOAD = Path("/tmp/opencode/irlume-1046-native-payload")
BASE = "/tmp/irlume-1046-libvirt-base-20261027/base.img"
DATA = "/var/lib/libvirt/images/irlume-1046-native-20261028"
RAM = "/tmp/irlume-1046-native-inputs-20261028"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


for source, target in [
    ("/tmp/opencode/irlume-1046-native-guest.py", "runner.py"),
    (
        "/tmp/opencode/irlume_1046_native_preflight.py",
        "helpers/irlume_1046_native_preflight.py",
    ),
    (
        "/tmp/opencode/irlume_1046_native_result.py",
        "helpers/irlume_1046_native_result.py",
    ),
]:
    (PAYLOAD / target).write_bytes(Path(source).read_bytes())
manifest = json.loads((PAYLOAD / "manifest.json").read_text())
manifest["files"] = {
    str(path.relative_to(PAYLOAD)): sha(path)
    for path in PAYLOAD.rglob("*")
    if path.is_file() and not path.is_symlink() and path.name != "manifest.json"
}
(PAYLOAD / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
(ROOT / "native-payload-manifest-final.json").write_text(
    json.dumps(manifest, indent=2) + "\n"
)
iso = Path("/tmp/opencode/irlume-1046-native-payload.iso")
assert not iso.exists()
subprocess.run(
    [
        "xorriso",
        "-as",
        "mkisofs",
        "-quiet",
        "-o",
        str(iso),
        "-V",
        "IRLUME_PAYLOAD",
        "-r",
        "-J",
        "-uid",
        "0",
        "-gid",
        "0",
        str(PAYLOAD),
    ],
    check=True,
    capture_output=True,
)
identifier = str(uuid.uuid4())
seed = ROOT / "seed"
seed.mkdir()
previous = Path(
    "/home/wisbfime/archledger-gp/experiments/irlume-1046-npu-vfio-20261027/managed/passthrough/user-data"
)
prior = json.loads(previous.read_text().split("\n", 1)[1])
firmware = [
    item
    for item in prior["write_files"]
    if item["path"].startswith("/lib/firmware/intel/vpu/")
]
assert {item["path"] for item in firmware} == {
    "/lib/firmware/intel/vpu/vpu_40xx_v1.bin.zst",
    "/lib/firmware/intel/vpu/vpu_40xx_v0.0.bin.zst",
}
firmware_deb = (
    previous.parents[2]
    / "ubuntu-package-metadata/linux-firmware-intel-misc_20260319.git217ca6e4-0ubuntu1.2_all.deb"
)
assert (
    sha(firmware_deb)
    == "ac543f729a90c36c9916bc573b874700f060c472ce68883c56356971a7db7092"
)
process = subprocess.Popen(
    ["dpkg-deb", "--fsys-tarfile", str(firmware_deb)], stdout=subprocess.PIPE
)
firmware_bytes = None
with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
    for entry in archive:
        if entry.name == "./usr/lib/firmware/intel/vpu/vpu_40xx_v1.bin.zst":
            assert entry.isfile() and entry.size <= 1_000_000
            firmware_bytes = archive.extractfile(entry).read()
process.stdout.close()
assert process.wait() == 0 and firmware_bytes is not None
assert all(
    base64.b64decode(item["content"], validate=True) == firmware_bytes
    for item in firmware
)
wrapper = """#!/bin/sh
set -eu
if [ "$(id -u)" != 0 ] || [ "$(hostname)" != irlume-aa-native ] || [ "$(systemd-detect-virt --vm)" != kvm ]; then
    exit 125
fi
trap 'sync; systemctl poweroff' EXIT
mkdir -p /mnt/payload /mnt/evidence
mount -t iso9660 -o ro,nosuid,nodev,noexec /dev/vdc /mnt/payload
mount -t vfat -o rw,nosuid,nodev,noexec /dev/vdd /mnt/evidence
set +e
timeout --kill-after=20 340 python3 -I -B /mnt/payload/runner.py
status=$?
echo IRLUME_NATIVE_STATUS=$status
sync
umount /mnt/evidence
exit "$status"
"""
config = {
    "users": [],
    "disable_root": True,
    "ssh_pwauth": False,
    "package_update": False,
    "package_upgrade": False,
    "write_files": firmware,
    "runcmd": [["sh", "-c", wrapper]],
}
(seed / "user-data").write_text("#cloud-config\n" + json.dumps(config) + "\n")
(seed / "meta-data").write_text(
    "instance-id: " + identifier + "\nlocal-hostname: irlume-aa-native\n"
)
subprocess.run(
    [
        "xorriso",
        "-as",
        "mkisofs",
        "-quiet",
        "-o",
        str(ROOT / "seed.iso"),
        "-V",
        "cidata",
        "-r",
        "-J",
        "user-data",
        "meta-data",
    ],
    cwd=seed,
    check=True,
    capture_output=True,
)
xml = f'''<domain type="kvm">
<name>irlume-aa-native</name><uuid>{identifier}</uuid>
<memory unit="MiB">4096</memory><currentMemory unit="MiB">4096</currentMemory><vcpu>2</vcpu>
<memtune><hard_limit unit="MiB">6144</hard_limit></memtune><cputune><global_period>100000</global_period><global_quota>200000</global_quota></cputune>
<os><type arch="x86_64" machine="q35">hvm</type><boot dev="hd"/></os><features><acpi/><apic/></features><cpu mode="host-passthrough"/><clock offset="utc"/>
<on_poweroff>destroy</on_poweroff><on_reboot>destroy</on_reboot><on_crash>destroy</on_crash>
<devices><emulator>/usr/bin/qemu-system-x86_64</emulator>
<disk type="file" device="disk"><driver name="qemu" type="qcow2"/><source file="{RAM}/guest.qcow2"/><target dev="vda" bus="virtio"/><backingStore type="file"><format type="qcow2"/><source file="{BASE}"/><backingStore/></backingStore></disk>
<disk type="file" device="disk"><driver name="qemu" type="raw"/><source file="{DATA}/seed.iso"/><target dev="vdb" bus="virtio"/><readonly/></disk>
<disk type="file" device="disk"><driver name="qemu" type="raw"/><source file="{RAM}/payload.iso"/><target dev="vdc" bus="virtio"/><readonly/></disk>
<disk type="file" device="disk"><driver name="qemu" type="raw"/><source file="{DATA}/evidence.img"/><target dev="vdd" bus="virtio"/></disk>
<serial type="pty"><target port="0"/></serial><console type="pty"><target type="serial" port="0"/></console>
<video><model type="none"/></video><memballoon model="none"/>
<hostdev mode="subsystem" type="pci" managed="yes"><driver name="vfio"/><source><address domain="0x0000" bus="0x00" slot="0x0b" function="0x0"/></source></hostdev>
</devices><seclabel type="dynamic" model="selinux" relabel="yes"/></domain>
'''
(ROOT / "domain.xml").write_text(xml)
subprocess.run(["virt-xml-validate", str(ROOT / "domain.xml"), "domain"], check=True)
record = {
    "uuid": identifier,
    "xml_sha256": sha(ROOT / "domain.xml"),
    "seed_sha256": sha(ROOT / "seed.iso"),
    "payload": {"path": str(iso), "sha256": sha(iso), "bytes": iso.stat().st_size},
    "native_case_count": 2,
    "negative_controls": 2,
    "planned_native_inferences": 12,
    "native_started": False,
}
(ROOT / "inputs.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record, indent=2))

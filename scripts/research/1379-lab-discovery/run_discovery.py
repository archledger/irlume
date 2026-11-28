"""Bounded launcher and receipt verifier for the Book 2 discovery guest (B03)."""

from collections import Counter
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "1379-lab-boot"))
import run_guest  # noqa: E402  (pinned QEMU path, version and scratch checks)

PROTOCOL = "BOOK2_DISCOVERY_V1"
MAX_SERIAL = 8 * 1024 * 1024
TIMEOUT = 180
PREFIX = ("PID1", "DENY_ATTACHED", "PRE_INVENTORY_DENIED", "INTENT_RECORDED")
GRAPH_KINDS = ("media", "entity", "node", "link")
LAB = PREFIX + ("RESERVED",)
KNOWN = ("OWNER_RELEASED", "SECOND_BACKEND_STARTED", "IR_STUB_RAN")
BLOCKED = ("SECOND_BACKEND_BLOCKED unknown",)
REPLACED = "REPLACED same_devt=1 same_version=1 new_inode=1"
WORKER_EFFECTS = ("ctrl", "link", "fmt", "sel")
KERNEL_FAULT = re.compile(
    r"Kernel panic|\bOops\b|\bBUG:|\bWARNING:|\bKASAN\b|circular locking|INFO: possible|"
    r"INFO: trying to register|INFO: task .* blocked|general protection fault|Call Trace:")
EFFECT = re.compile(r"EFFECT ([0-9]+) ([0-9]+) (worker|supervisor|other) (\S.*)")
END = re.compile(r"EFFECTS_END ([0-9]+) dropped=([0-9]+)")


@dataclass(frozen=True)
class Case:
    image: str
    params: tuple[str, ...]
    events: tuple[str, ...]


@dataclass(frozen=True)
class Receipt:
    events: tuple[str, ...]
    effects: tuple[str, ...]
    topology: tuple[str, ...]


CASES = {
    "topology": Case("lab.cpio", (), PREFIX + ("TOPOLOGY_READ",)),
    "sim-controls": Case("lab.cpio", (), PREFIX + (
        "REPLACED same_devt=1 same_version=1 new_inode=1", "VERSION_BUMPED",
        "EXTRA_MEDIA_PRESENT", "SIM_CONTROLS_PASS")),
    "stock-baseline": Case("stock.cpio", (), PREFIX + (
        "IR_LINK_ENABLED", "WORKER_READY", "CAMERAS 2", "WORKER_EXITED 0", "STOCK_EFFECTS_OBSERVED")),
    "lab-front": Case("lab.cpio", (), LAB + (
        "WORKER_READY", "CAMERAS 1", "WORKER_EXITED 0", "GUARD admit") + KNOWN),
    "graph-ir-link-enabled": Case("lab.cpio", (), LAB + (
        "IR_LINK_ENABLED", "WORKER_READY", "CAMERAS 0", "WORKER_EXITED 0", "GUARD refuse link-state",
        "HOLD link-state") + BLOCKED),
    "graph-extra-entity": Case("lab.cpio", (), LAB + (
        "ENTITY_ADDED", "WORKER_READY", "CAMERAS 0", "WORKER_EXITED 0", "GUARD refuse version",
        "HOLD version") + BLOCKED),
    "hotplug-extra-media": Case("lab.cpio", (), LAB + (
        "MEDIA_ADDED", "WORKER_READY", "CAMERAS 0", "WORKER_EXITED 0", "GUARD refuse unreserved-open",
        "HOLD media-set") + BLOCKED),
    "sim-port-variant": Case("lab.cpio", ("book2_lab_sim.front_port=3",), PREFIX + (
        "REFUSED_CONTRACT_GRAPH", "REFUSED_BEFORE_RESERVATION", "SECOND_BACKEND_BLOCKED refused")),
    "effect-unlisted-link": Case("lab.cpio", (), LAB + (
        "WORKER_READY", "CAMERAS 0", "WORKER_EXITED 0",
        "GUARD refuse unlisted-effect link cio2 ov5693_2-0036:0 ipu3-csi2_0:0 0x1",
        "HOLD partial-effects") + BLOCKED),
    "replace-before-discovery": Case("lab.cpio", (), LAB + (
        REPLACED, "WORKER_READY", "CAMERAS 0", "WORKER_EXITED 0", "GUARD refuse identity",
        "HOLD replaced") + BLOCKED),
    "generation-during-discovery": Case("lab.cpio", (), LAB + (
        "BUMP_ARMED", "WORKER_READY", "CAMERAS 0", "WORKER_EXITED 0", "GUARD hold version",
        "HOLD version") + BLOCKED),
    "replace-after-discovery": Case("lab.cpio", (), LAB + (
        "WORKER_READY", "CAMERAS 1", "REPLACED_AFTER_DISCOVERY", "WORKER_EXITED 0", "GUARD admit",
        "HOLD replaced") + BLOCKED),
}


def _sections(path: Path) -> dict[str, tuple[str, ...]]:
    sections: dict[str, list[str]] = {}
    current = None
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            if current in sections:
                raise ValueError(f"duplicate expectation section {current}")
            sections[current] = []
        elif current is None:
            raise ValueError("expectation record outside a section")
        else:
            sections[current].append(line)
    return {name: tuple(lines) for name, lines in sections.items()}


def expected_effects(case: str) -> tuple[str, ...]:
    sections = _sections(HERE / "contract" / "expected-effects.txt")
    if case not in sections:
        raise ValueError(f"no effect expectation for {case}")
    return sections[case]


def graph_records() -> tuple[str, ...]:
    lines = (HERE / "contract" / "front.contract").read_text().splitlines()
    return tuple(line for line in lines if line.split(" ", 1)[0] in GRAPH_KINDS)


def _split_releases(records):
    ordered = tuple(r for r in records if r.split(" ")[2:3] != ["release"])
    return ordered, Counter(r for r in records if r.split(" ")[2:3] == ["release"])


def check_outcome(events: tuple[str, ...], effects: tuple[str, ...]) -> None:
    """Outcome rules that hold for every case, independent of the case table."""
    worker_effects = [e for e in effects if e.split(" ")[1:3][0:1] == ["worker"] and e.split(" ")[2] in WORKER_EFFECTS]
    holds = [e for e in events if e.startswith("HOLD ")]
    if "RELEASED_AFTER_REFUSAL" in events and worker_effects:
        raise ValueError("release after refusal despite worker effects")
    if holds and ("SECOND_BACKEND_STARTED" in events or BLOCKED[0] not in events):
        raise ValueError("second backend not blocked after a hold")
    if "SECOND_BACKEND_STARTED" in events and "OWNER_RELEASED" not in events[:events.index("SECOND_BACKEND_STARTED")]:
        raise ValueError("second backend started without a known owner release")
    for e in events:
        if e.startswith("REPLACED ") and e != REPLACED:
            raise ValueError(f"replacement receipt does not prove same number and new inode: {e}")


def check_discovery(text: str, nonce: str, case: str, returncode: int) -> Receipt:
    if case not in CASES:
        raise ValueError(f"unknown discovery case {case!r}")
    if returncode != 0:
        raise ValueError(f"guest failed ({returncode=})")
    if KERNEL_FAULT.search(text):
        raise ValueError("kernel fault or warning report in serial log")
    prefix = f"{PROTOCOL} {nonce} "
    events, effects, topology = [], [], []
    ended = False
    for line in text.splitlines():
        if not line.startswith("BOOK2_"):
            continue
        if not line.startswith(prefix):
            raise ValueError("unexpected receipt nonce or protocol")
        if ended:
            raise ValueError("record after the effect dump")
        body = line[len(prefix):]
        if match := EFFECT.fullmatch(body):
            if int(match[1]) != len(effects) + 1:
                raise ValueError("effect sequence gap or duplicate")
            if match[3] == "other":
                raise ValueError("effect from an unexpected process")
            effects.append(f"{match[2]} {match[3]} {match[4]}")
        elif match := END.fullmatch(body):
            if int(match[1]) != len(effects) or int(match[2]) != 0:
                raise ValueError("effect log count mismatch or dropped records")
            ended = True
        elif body.startswith("TOPOLOGY "):
            topology.append(body[len("TOPOLOGY "):])
        else:
            events.append(body)
    if not ended:
        raise ValueError("missing effect dump")
    check_outcome(tuple(events), tuple(effects))
    if tuple(events) != CASES[case].events:
        raise ValueError(f"unexpected receipt sequence for {case}: {tuple(events)}")
    if _split_releases(effects) != _split_releases(expected_effects(case)):
        raise ValueError(f"unexpected effect records for {case}: {tuple(effects)}")
    want_topology = sorted(graph_records()) if case == "topology" else []
    if sorted(topology) != want_topology:
        raise ValueError("topology does not match the contract graph")
    return Receipt(tuple(events), tuple(effects), tuple(topology))


def qemu_args(kernel: Path, initramfs: Path, serial: Path, case: str, nonce: str) -> list[str]:
    for path in (kernel, initramfs, serial):
        if not path.is_relative_to("/tmp/opencode") or re.fullmatch(r"/[a-zA-Z0-9._/-]+", str(path)) is None:
            raise ValueError("QEMU input/output paths must be plain absolute scratch paths")
    if case not in CASES or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("invalid discovery case or nonce")
    spec = CASES[case]
    if initramfs.name != spec.image:
        raise ValueError(f"{case} must boot {spec.image}")
    append = " ".join(("console=ttyS0", "rdinit=/init", "panic=-1", "panic_on_warn=1",
                       "kasan.fault=panic", f"book2_case={case}", f"book2_nonce={nonce}") + spec.params)
    return [
        run_guest.QEMU, "-machine", "q35,accel=tcg", "-m", "1024", "-smp", "1",
        "-nodefaults", "-display", "none", "-monitor", "none", "-nic", "none", "-no-reboot",
        "-kernel", str(kernel), "-initrd", str(initramfs), "-serial", f"file:{serial}",
        "-append", append,
    ]


def verify_build(build: Path, image: str) -> tuple[Path, Path]:
    manifest = build / "build.sha256"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("missing build manifest")
    listed = {}
    for line in manifest.read_text().splitlines():
        digest, _, name = line.partition("  ")
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None or "/" in name or name in listed:
            raise ValueError("malformed build manifest")
        listed[name] = digest
    if "bzImage" not in listed or image not in listed:
        raise ValueError(f"build manifest lacks bzImage or {image}")
    for name, digest in listed.items():
        path = build / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"expected regular guest artifact: {name}")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError(f"guest artifact digest mismatch: {name}")
    return build / "bzImage", build / image


def run_discovery(build: Path, receipt: Path, case: str) -> Receipt:
    if os.geteuid() == 0:
        raise ValueError("run as an ordinary host user")
    if case not in CASES:
        raise ValueError(f"unknown discovery case {case!r}")
    kernel, initramfs = verify_build(build, CASES[case].image)
    nonce = secrets.token_hex(16)
    serial = receipt / "serial.log"
    args = qemu_args(kernel, initramfs, serial, case, nonce)
    receipt.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin", "LC_ALL": "C", "HOME": str(receipt)}
    opts = dict(stdin=subprocess.DEVNULL, close_fds=True, env=env)
    version = subprocess.run((run_guest.QEMU, "--version"), capture_output=True, text=True,
                             check=True, timeout=10, **opts).stdout.splitlines()
    if not version or not (version[0] == run_guest.VERSION or version[0].startswith(run_guest.VERSION + " ")):
        raise ValueError("QEMU version drift: review the exact invocation before boot")
    (receipt / "invocation.txt").write_text(version[0] + "\n" + "\n".join(args) + "\n")
    with (receipt / "qemu.log").open("w") as log:
        result = subprocess.run(args, timeout=TIMEOUT, stdout=log, stderr=log, **opts)
    if not serial.is_file() or serial.stat().st_size > MAX_SERIAL:
        raise ValueError("missing or oversized guest serial log")
    verified = check_discovery(serial.read_text(errors="replace"), nonce, case, result.returncode)
    (receipt / "verified.txt").write_text(
        f"{nonce} {case}\n" + "\n".join(verified.events + verified.effects) + "\n")
    return verified


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: run_discovery.py BUILD_DIR NEW_RECEIPT_DIR CASE")
    try:
        result = run_discovery(run_guest.scratch_path(sys.argv[1], exists=True),
                               run_guest.scratch_path(sys.argv[2], exists=False), sys.argv[3])
        print(f"Verified discovery guest {sys.argv[3]}: {', '.join(result.events)}; "
              f"{len(result.effects)} effect records")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Discovery guest proof refused: {error}")

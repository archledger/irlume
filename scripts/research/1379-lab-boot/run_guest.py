import hashlib
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys


QEMU = "/usr/bin/qemu-system-x86_64"
VERSION = "QEMU emulator version 11.1.3"
POLICY_EVENTS = (
    "PID1", "DENY_ATTACHED", "PRE_INVENTORY_DENIED", "DUMMY_IDENTIFIED",
    "WORKER_POLICY_ATTACHED", "ALIAS_ACCESS_CHECKED", "REPLACEMENT_REFUSED", "POLICY_PASS",
)
CASE_EVENTS = {
    "smoke": ("PID1", "SMOKE_ONLY"),
    "missing-deny": ("PID1", "REFUSED_NO_INITIAL_POLICY"),
    "policy": POLICY_EVENTS,
    "kept-fd": POLICY_EVENTS + ("REFUSED_RETAINED_HANDLE",),
    "boundary": POLICY_EVENTS + (
        "INHERITED_HANDLE_CLOSED", "PEER_PROC_LINK_DENIED", "PEER_HANDLE_DENIED",
        "FD_IPC_POSITIVE", "FD_IPC_DENIED", "BOOT_BOUNDARY_PASS",
    ),
}
MAX_SERIAL = 2 * 1024 * 1024
NON_PRINTABLE = re.compile(r"[^\x20-\x7e]")


def read_serial(path: Path) -> str:
    """The serial log as written: no newline translation, so only '\\n' ends a line."""
    return path.read_bytes().decode("utf-8", errors="replace")


def receipt_lines(text: str) -> list[str]:
    """Split on '\\n' only, dropping the one '\\r' of the console's line ending."""
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def check_receipt(text: str, nonce: str, case: str, returncode: int) -> tuple[str, ...]:
    if returncode != 0 or "Kernel panic" in text or re.search(r"\bOops:", text):
        raise ValueError(f"guest failed or panicked ({returncode=})")
    prefix = f"BOOK2_BOOT_V1 {nonce} "
    events = []
    for line in receipt_lines(text):
        if not line.startswith("BOOK2_BOOT_"):
            continue
        if NON_PRINTABLE.search(line):
            raise ValueError("control character in receipt line")
        if not line.startswith(prefix):
            raise ValueError("unexpected guest receipt nonce or protocol")
        events.append(line[len(prefix):])
    actual = tuple(events)
    if actual != CASE_EVENTS.get(case):
        raise ValueError(f"unexpected receipt sequence for {case}: {actual}")
    return actual


def qemu_args(kernel: Path, initramfs: Path, serial: Path, case: str, nonce: str) -> list[str]:
    for path in (kernel, initramfs, serial):
        if not path.is_relative_to("/tmp/opencode") or re.fullmatch(r"/[a-zA-Z0-9._/-]+", str(path)) is None:
            raise ValueError("QEMU input/output paths must be plain absolute scratch paths")
    if case not in CASE_EVENTS or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("invalid dummy fixture case or nonce")
    return [
        QEMU, "-machine", "q35,accel=tcg", "-m", "512", "-smp", "1",
        "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none", "-nic", "none",
        "-no-reboot", "-kernel", str(kernel), "-initrd", str(initramfs), "-serial", f"file:{serial}",
        "-append", f"console=ttyS0 rdinit=/init panic=-1 book2_case={case} book2_nonce={nonce}",
    ]


def verify_build(build: Path) -> tuple[Path, Path]:
    files = (build / "bzImage", build / "initramfs.cpio")
    lines = []
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"expected regular guest artifact: {path.name}")
        with path.open("rb") as stream:
            lines.append(f"{hashlib.file_digest(stream, 'sha256').hexdigest()}  {path.name}\n")
    manifest = build / "build.sha256"
    if manifest.is_symlink() or manifest.read_text() != "".join(lines):
        raise ValueError("guest artifact digest mismatch")
    return files


def scratch_path(text: str, *, exists: bool) -> Path:
    path = Path(text)
    if not path.is_absolute() or not path.is_relative_to("/tmp/opencode") or path == Path("/tmp/opencode"):
        raise ValueError("guest work must stay in a private /tmp/opencode directory")
    if path.resolve(strict=exists) != path or ".." in path.parts:
        raise ValueError("use canonical scratch paths")
    return path


def run_guest(build: Path, receipt: Path, case: str) -> tuple[str, ...]:
    if os.geteuid() == 0:
        raise ValueError("run as an ordinary host user")
    kernel, initramfs = verify_build(build)
    nonce = secrets.token_hex(16)
    serial = receipt / "serial.log"
    args = qemu_args(kernel, initramfs, serial, case, nonce)
    receipt.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin", "LC_ALL": "C", "HOME": str(receipt)}
    opts = dict(stdin=subprocess.DEVNULL, close_fds=True, env=env)
    version = subprocess.run(
        (QEMU, "--version"), capture_output=True, text=True, check=True, timeout=10, **opts,
    ).stdout.splitlines()
    if not version or not (version[0] == VERSION or version[0].startswith(VERSION + " ")):
        raise ValueError("QEMU version drift: review the exact invocation before boot")
    (receipt / "invocation.txt").write_text(version[0] + "\n" + "\n".join(args) + "\n")
    with (receipt / "qemu.log").open("w") as log:
        result = subprocess.run(args, timeout=60, stdout=log, stderr=log, **opts)
    if not serial.is_file() or serial.stat().st_size > MAX_SERIAL:
        raise ValueError("missing or oversized guest serial log")
    events = check_receipt(read_serial(serial), nonce, case, result.returncode)
    (receipt / "verified.txt").write_text(f"{nonce} {case}\n" + "\n".join(events) + "\n")
    return events


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: run_guest.py BUILD_DIR NEW_RECEIPT_DIR CASE")
    try:
        events = run_guest(scratch_path(sys.argv[1], exists=True),
                           scratch_path(sys.argv[2], exists=False), sys.argv[3])
        print(f"Verified dummy guest {sys.argv[3]}: {', '.join(events)}")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Dummy guest proof refused: {error}")

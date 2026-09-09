"""Linux host checks and an exclusive, durable attempt ledger.

Private host paths and service state stay in memory, never in result records.
The root operator owns the configuration and reviews its preservation scope.
"""

import errno
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
ASSETS = {"binary", "detector", "recognizer", "flir", "ort"}


def strict_json(text):
    def pairs(items):
        data = {}
        for key, value in items:
            if key in data:
                raise ValueError("duplicate_key")
            data[key] = value
        return data

    return json.loads(text, object_pairs_hook=pairs)


def validate_config(data):
    if not isinstance(data, dict) or set(data) != {
        "schema",
        "subject_uid",
        "budget_ms",
        "watchdog_seconds",
        "assets",
        "cameras",
        "protected_files",
        "service",
    }:
        raise ValueError("invalid_config")
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise ValueError("invalid_config")
    for key, low, high in [
        ("subject_uid", 1, 2**32 - 2),
        ("budget_ms", 100, 30000),
        ("watchdog_seconds", 1, 120),
    ]:
        if type(data[key]) is not int or not low <= data[key] <= high:
            raise ValueError("invalid_config")
    if data["watchdog_seconds"] * 1000 <= data["budget_ms"]:
        raise ValueError("invalid_config")
    assets = data["assets"]
    if (
        not isinstance(assets, dict)
        or not ASSETS <= assets.keys()
        or assets.keys() - ASSETS - {"adapter"}
    ):
        raise ValueError("invalid_config")
    for asset in assets.values():
        if (
            not isinstance(asset, dict)
            or set(asset) != {"path", "sha256"}
            or not absolute_path(asset["path"])
            or not isinstance(asset["sha256"], str)
            or re.fullmatch("[a-f0-9]{64}", asset["sha256"]) is None
        ):
            raise ValueError("invalid_config")
    cameras = data["cameras"]
    if not isinstance(cameras, dict) or set(cameras) != {"rgb", "ir", "metadata"}:
        raise ValueError("invalid_config")
    if (
        any(
            not isinstance(node, str) or re.fullmatch("/dev/video[0-9]+", node) is None
            for node in cameras.values()
        )
        or len(set(cameras.values())) != 3
    ):
        raise ValueError("invalid_config")
    paths = data["protected_files"]
    if (
        not isinstance(paths, list)
        or not 1 <= len(paths) <= 256
        or not all(absolute_path(path) for path in paths)
        or len(set(paths)) != len(paths)
    ):
        raise ValueError("invalid_config")
    if data["service"] != "irlumed.service":
        raise ValueError("invalid_config")
    return data


def absolute_path(value):
    return (
        isinstance(value, str)
        and value.startswith("/")
        and "\x00" not in value
        and len(value) <= 4096
        and ".." not in Path(value).parts
    )


def trusted_path(path):
    """Validate every component and symlink hop before following it."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("untrusted_path")
    pending = list(path.parts[1:])
    current = Path("/")
    hops = 0
    while True:
        info = current.lstat()
        if info.st_uid != 0 or (
            not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022
        ):
            raise ValueError("untrusted_path")
        if stat.S_ISLNK(info.st_mode):
            hops += 1
            if hops > 40:
                raise ValueError("symlink_loop")
            target = Path(os.readlink(current))
            current = Path("/") if target.is_absolute() else current.parent
            pending = (
                list(target.parts[1:] if target.is_absolute() else target.parts)
                + pending
            )
            continue
        if not pending:
            return current
        part = pending.pop(0)
        current = current.parent if part == ".." else current / part


def file_identity(path):
    canonical = trusted_path(path)
    info = canonical.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("not_regular_file")
    digest = hashlib.sha256()
    with canonical.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return (
        str(canonical),
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
        digest.hexdigest(),
    )


def qualified_topology(nodes, cameras):
    ir, meta, rgb = (nodes[key] for key in ["ir", "metadata", "rgb"])
    siblings = {Path(cameras["ir"]).name, Path(cameras["metadata"]).name}
    return (
        ir["index"] == rgb["index"] == 0
        and meta["index"] == 1
        and ir["interface"] == meta["interface"] != rgb["interface"]
        and ir["siblings"] == meta["siblings"] == siblings
        and all("/virtual/" not in node["interface"] for node in nodes.values())
    )


def topology(cameras):
    nodes = {}
    for role, device in cameras.items():
        info = Path(device).lstat()
        if not stat.S_ISCHR(info.st_mode) or os.major(info.st_rdev) != 81:
            raise ValueError("unsupported_topology")
        node = Path("/sys/class/video4linux") / Path(device).name
        if (
            node.joinpath("dev").read_text().strip()
            != f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        ):
            raise ValueError("unsupported_topology")
        interface = node.joinpath("device").resolve(strict=True)
        nodes[role] = {
            "index": int((node / "index").read_text()),
            "interface": str(interface),
            "siblings": {p.name for p in (interface / "video4linux").iterdir()},
        }
    if not qualified_topology(nodes, cameras):
        raise ValueError("unsupported_topology")
    return nodes


def command_output(command):
    got = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=ENV,
        timeout=5,
        check=False,
    )
    if got.returncode != 0 or len(got.stdout) > 16384:
        raise ValueError("host_check_failed")
    return got.stdout.decode("ascii").strip()


def idle():
    devices = sorted(str(path) for path in Path("/dev").glob("video[0-9]*"))
    if not devices:
        raise ValueError("camera_idle_unverified")
    # fuser's status alone also covers operational errors; require no stderr.
    got = subprocess.run(
        ["/usr/bin/fuser", *devices],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        timeout=5,
        check=False,
    )
    if got.returncode != 1 or got.stdout.strip() or got.stderr.strip():
        raise ValueError("camera_idle_unverified")


def security_state(process, lsm_list=Path("/sys/kernel/security/lsm")):
    """Preserve labels when supported, and distinguish verified absence from errors."""
    modules = lsm_list.read_text().strip()
    names = modules.split(",")
    if not modules or any(re.fullmatch("[a-z0-9_]+", name) is None for name in names):
        raise ValueError("invalid_lsm_list")
    try:
        context = (process / "attr/current").read_text().strip()
    except OSError as error:
        # The observed configuration returns getprocattr's EINVAL default
        # without a process label. Restrict absence to this reviewed module set;
        # do not generalize to unknown providers, missing files or access denial.
        reviewed_modules = {"capability", "landlock", "lockdown", "yama", "bpf"}
        if error.errno != errno.EINVAL or not set(names) <= reviewed_modules:
            raise
        context = None
    return {"modules": modules, "context": context}


def snapshot(config):
    assets = {
        key: file_identity(asset["path"]) for key, asset in config["assets"].items()
    }
    if any(
        assets[key][-1] != value["sha256"] for key, value in config["assets"].items()
    ):
        raise ValueError("asset_hash_mismatch")
    protected = {path: file_identity(path) for path in config["protected_files"]}
    nodes = topology(config["cameras"])
    idle()
    service = command_output(
        [
            "/usr/bin/systemctl",
            "show",
            config["service"],
            "--property=MainPID,ActiveState,SubState,NRestarts",
        ]
    )
    fields = dict(line.split("=", 1) for line in service.splitlines())
    if fields.get("ActiveState") != "active" or fields.get("SubState") != "running":
        raise ValueError("service_not_ready")
    pid = int(fields["MainPID"])
    if pid <= 1:
        raise ValueError("service_not_ready")
    status = Path(f"/proc/{pid}/status").read_text()
    security = tuple(
        line
        for line in status.splitlines()
        if line.startswith(("Uid:", "Gid:", "Cap", "NoNewPrivs:", "Seccomp:"))
    )
    lsm = security_state(Path(f"/proc/{pid}"))
    enforce = Path("/sys/fs/selinux/enforce")
    selinux = enforce.read_text().strip() if enforce.exists() else "unavailable"
    return {
        "assets": assets,
        "protected": protected,
        "nodes": nodes,
        "service": service,
        "security": security,
        "lsm": lsm,
        "selinux": selinux,
    }


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path, data):
    # A crash can leave incomplete JSON; the ledger then blocks further scans.
    with open(path, "x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(data, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


class Ledger:
    def __init__(self, directory):
        self.directory = Path(directory)

    def reserve(self, label, mode, campaign, identity):
        if re.fullmatch("[a-z0-9][a-z0-9-]{0,63}", label) is None:
            raise ValueError("invalid_attempt_id")
        for old in self.directory.iterdir():
            if (
                old.is_symlink()
                or not old.is_dir()
                or not (old / "started.json").is_file()
            ):
                raise ValueError("ledger_requires_review")
            try:
                result = strict_json((old / "final.json").read_text())
                if (
                    result.get("stop_required") is not False
                    or result.get("status") != "complete"
                ):
                    raise ValueError("ledger_requires_review")
            except (OSError, ValueError, AttributeError) as exc:
                raise ValueError("ledger_requires_review") from exc
        attempt = self.directory / label
        attempt.mkdir(mode=0o700)
        sync_directory(self.directory)
        write_exclusive(
            attempt / "started.json",
            {
                "schema": 1,
                "mode": mode,
                "campaign": campaign,
                "binary_sha256": identity,
                "status": "started",
            },
        )
        return attempt

    def finish(self, attempt, result):
        write_exclusive(attempt / "final.json", result)

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Pure rooted-G profile and partial witness checks, not execution authority.

No collectors, service creation, READY admission or runtime qualification live
here. Callers must retain the selected inputs and obtain observations themselves.
"""

import importlib.machinery
import importlib.util
import re
import stat
from pathlib import Path
from typing import NamedTuple


class SourceLoader(importlib.machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path), self.path)


def load(name, filename):
    loader = SourceLoader(name, str(Path(__file__).with_name(filename)))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


closure = load("root_closure", "measurement-job-closure.py")
guardian = load("root_guardian", "measurement-job-guardian.py")
runtime = closure.runtime
DENIED = (
    "/dev/pts",
    "/dev/ptmx",
    "/dev/shm",
    "/dev/mqueue",
    "/dev/hugepages",
    "/sys/fs/selinux",
    "/run/credentials",
)
NAMESPACES = ("pid", "user", "mnt", "net", "cgroup")
# Absent from a subset=pid proc; still observed as denial nodes.
KERNEL_DENIED = ("/proc/kallsyms", "/proc/kcore")
# Covered with InaccessiblePaths=-+PATH. ProcSubset=pid leaves no /proc/sys, so
# only sysfs views are listed.
KERNEL_HIDDEN = (
    "/sys/firmware/efi/efivars",
    "/sys/fs/bpf",
    "/sys/fs/fuse/connections",
    "/sys/fs/pstore",
    "/sys/fs/smackfs",
    "/sys/kernel/config",
    "/sys/kernel/debug",
    "/sys/kernel/security",
    "/sys/kernel/tracing",
)
# Every path G observes as a denial: absent, or covered by an inaccessible node.
DENIAL_NODES = (*DENIED, *KERNEL_DENIED, *KERNEL_HIDDEN)
DEVICE_BINDS = tuple(
    "/dev/" + name for name in ("null", "zero", "full", "random", "urandom", "tty")
)
# A host cgroup v1 hierarchy (a VPN's net_cls for split tunnelling) shows
# through the read-only cgroup2 mount as one child mount.
LEGACY_CGROUPS = (
    "/sys/fs/cgroup/net_cls",
    "/sys/fs/cgroup/net_cls,net_prio",
    "/sys/fs/cgroup/net_prio",
)
# systemd's inaccessible nodes, in the manager's runtime directory.
INACCESSIBLE = re.compile(
    r"((?:/[^/]+)*)/systemd/inaccessible/(dir|reg|chr|blk|fifo|sock)"
)
SEALED = frozenset({"ro", "nosuid", "nodev", "noexec"})
# The one kernel view whose cover may hide mounts (occluded_debugfs).
DEBUGFS = "/sys/kernel/debug"
TRACING = DEBUGFS + "/tracing"
ATTEMPT = "/run/irlume/attempt"
OS_RELEASE_STAGE = "/run/host/.os-release-stage"
ENTRY = "opt/irlume/measurement-job-guardian-native.py"
# Linux UAPI linux/mount.h. Explicitly override systemd's namespace-local shared default.
MS_PRIVATE = 1 << 18
# systemd v259.10 and v262.1 src/core/dbus-execute.c and dbus-cgroup.c.
# https://github.com/systemd/systemd/blob/v259.10/src/core/dbus-execute.c
# https://github.com/systemd/systemd/blob/v262.1/src/core/dbus-execute.c
PROPERTY_TYPES = {
    "MountFlags": "t",
    "RootDirectory": "s",
    "PrivateUsersEx": "s",
    "PrivateMounts": "b",
    "PrivateNetwork": "b",
    "PrivateDevices": "b",
    "PrivatePIDs": "s",
    "ProcSubset": "s",
    "ProtectProc": "s",
    "MountAPIVFS": "b",
    "BindLogSockets": "b",
    "ProtectSystem": "s",
    "ProtectHome": "s",
    "ProtectKernelTunables": "b",
    "ProtectKernelLogs": "b",
    "KeyringMode": "s",
    "ProtectControlGroups": "b",
    "RestrictNamespaces": "t",
    "CapabilityBoundingSet": "t",
    "AmbientCapabilities": "t",
    "DevicePolicy": "s",
    "DeviceAllow": "a(ss)",
    "BindPaths": "a(ssbt)",
    "BindReadOnlyPaths": "a(ssbt)",
    "TemporaryFileSystem": "a(ss)",
    "InaccessiblePaths": "as",
}


def absolute_path(value):
    if type(value) is not str or not value.startswith("/") or value == "/":
        raise ValueError("root plan absolute path")
    closure.relative_path(value[1:])
    if len(value) > 4096:
        raise ValueError("root plan path limit")
    return value


def identity(row, extra=()):
    runtime._fields(row, ("device", "inode", *extra))
    runtime._integer(row["device"], 0, runtime.U64_MAX)
    runtime._integer(row["inode"], 1, runtime.U64_MAX)
    return row["device"], row["inode"]


def digest(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("root plan digest")


def nested(path, parent):
    return path == parent or path.startswith(parent + "/")


def check_plan(plan):
    """Check selection shape only; a JSON plan cannot prove retained ownership."""
    runtime._fields(
        plan,
        (
            "scope",
            "run_id",
            "uid",
            "gid",
            "root",
            "attempt",
            "base",
            "payload",
            "manifest",
            "launcher",
            "host_namespaces",
            "host_api",
        ),
    )
    if type(plan["scope"]) is not str or plan["scope"] != "contained-job-root-plan-v1":
        raise ValueError("root plan scope")
    runtime._identifier(plan["run_id"])
    for key in ("uid", "gid"):
        runtime._integer(plan[key], 1, runtime.U32_MAX - 1)
    paths, identities = [], []
    for key in ("root", "attempt", "base", "payload", "manifest"):
        row = plan[key]
        identities.append(
            identity(row, ("path", "sha256") if key == "manifest" else ("path",))
        )
        paths.append(absolute_path(row["path"]))
    if len(set(identities)) != len(identities):
        raise ValueError("aliased root plan identities")
    for index, path in enumerate(paths):
        if any(
            nested(path, other) or nested(other, path) for other in paths[index + 1 :]
        ):
            raise ValueError("overlapping root plan paths")
    digest(plan["manifest"]["sha256"])
    runtime._fields(plan["launcher"], ("path", "sha256"))
    absolute_path(plan["launcher"]["path"])
    digest(plan["launcher"]["sha256"])
    runtime._fields(plan["host_namespaces"], NAMESPACES)
    for number in plan["host_namespaces"].values():
        runtime._integer(number, 1, runtime.U64_MAX)
    runtime._fields(plan["host_api"], (*DENIED, "/run", "/tmp"))
    for path, row in plan["host_api"].items():
        if row is not None or path in ("/run", "/tmp"):
            identity(row)


def check_selection(plan, manifest_data):
    check_plan(plan)
    manifest = closure.decode_manifest(manifest_data, plan["manifest"]["sha256"])
    if (
        manifest["python"]["entry"] != ENTRY
        or manifest["python"]["executable"] != "usr/bin/python3"
    ):
        raise ValueError("rooted guardian fixed Python entry")
    if "/" + manifest["bootstrap"] != plan["launcher"]["path"]:
        raise ValueError("rooted guardian bootstrap path")
    members = {member["path"]: member for member in manifest["members"]}
    for name in closure.ROOT_SCAFFOLD:
        if members.get(name) != {"path": name, "kind": "directory", "mode": 0o500}:
            raise ValueError("rooted runtime missing empty scaffold")
    if any(
        path.split("/")[0] in closure.API_ROOTS for path in manifest["python"]["roots"]
    ):
        raise ValueError("rooted Python search root overlaps API mount")
    for member in manifest["members"]:
        if (
            "/" in member["path"]
            and member["path"].split("/")[0] in closure.ROOT_SCAFFOLD
        ):
            raise ValueError("runtime member populates empty scaffold")
        if (
            member["path"] == manifest["bootstrap"]
            and member["sha256"] != plan["launcher"]["sha256"]
        ):
            raise ValueError("rooted guardian bootstrap digest")
    return manifest


def root_properties(plan):
    """Only the fixed inert profile. This API cannot opt into KVM access."""
    check_plan(plan)
    return {
        "MountFlags": MS_PRIVATE,
        "RootDirectory": plan["root"]["path"],
        "PrivateUsersEx": "self",
        "PrivateMounts": True,
        "PrivateNetwork": True,
        "PrivateDevices": True,
        # G is PID 1 of its own namespace on a fresh proc that lists only
        # its own processes (systemd exec-invoke.c setup_private_pids).
        "PrivatePIDs": "yes",
        "ProcSubset": "pid",
        "ProtectProc": "invisible",
        "MountAPIVFS": True,
        "BindLogSockets": False,
        "ProtectSystem": "strict",
        "ProtectHome": "read-only",
        "ProtectKernelTunables": True,
        "ProtectKernelLogs": True,
        # A user manager defaults to inherit: every service shares its session
        # keyring, which links the user keyring. private gives each invocation
        # a new one, linked to no user keyring and holding only systemd's
        # invocation_id key (systemd.exec).
        "KeyringMode": "private",
        "ProtectControlGroups": True,
        # Zero allows no namespace types; unset is all ones (nsflags.h).
        "RestrictNamespaces": 0,
        "CapabilityBoundingSet": 0,
        "AmbientCapabilities": 0,
        "DevicePolicy": "closed",
        "DeviceAllow": (),
        "BindPaths": ((plan["attempt"]["path"], ATTEMPT, False, 0),),
        # Only the selected inputs. G has no user-bus path: H makes every
        # manager call, and the private network namespace separates abstract
        # sockets, so neither G nor a later child can reach systemd --user.
        "BindReadOnlyPaths": tuple(
            (plan[key]["path"], target, False, 0)
            for key, target in (
                ("base", "/run/irlume/base.raw"),
                ("payload", "/run/irlume/payload.raw"),
                ("manifest", "/run/irlume/runtime-manifest.json"),
            )
        ),
        "TemporaryFileSystem": (
            ("/tmp", "rw,nosuid,nodev,noexec,size=16M,mode=1777"),
            ("/run", "rw,nosuid,nodev,noexec,size=16M,mode=0755"),
        ),
        "InaccessiblePaths": tuple("-+" + path for path in (*DENIED, *KERNEL_HIDDEN)),
    }


def service_properties(spec, plan, manifest_data):
    check_selection(plan, manifest_data)
    properties = guardian.service_properties(spec)
    if plan["run_id"] != spec.run_id:
        raise ValueError("root plan transaction")
    return {**properties, **root_properties(plan)}


def entry_argv(plan, config_sha256):
    check_plan(plan)
    digest(config_sha256)
    return (
        plan["launcher"]["path"],
        "--guardian",
        ATTEMPT + "/guardian-config.json",
        config_sha256,
    )


def wire_properties(plan):
    """Encode the root-only property vector, without creating or calling a bus.

    Jeepney 0.9.0 arrays require lists; immutable local tuples are not wire arrays.
    The existing R4 transport is deliberately not expanded by this pure encoder.
    """
    return [
        (
            name,
            (
                PROPERTY_TYPES[name],
                list(value) if PROPERTY_TYPES[name].startswith("a") else value,
            ),
        )
        for name, value in root_properties(plan).items()
    ]


def normal_variant(variant, signature):
    if type(variant) is not tuple or len(variant) != 2 or variant[0] != signature:
        raise ValueError("root property signature")
    value = variant[1]
    if signature in ("s", "b", "t"):
        if type(value) is not {"s": str, "b": bool, "t": int}[signature]:
            raise ValueError("root property scalar type")
        if signature == "s" and (len(value) > 4096 or "\0" in value):
            raise ValueError("root property string")
        if signature == "t":
            runtime._integer(value, 0, runtime.U64_MAX)
        return value
    if type(value) not in (tuple, list) or len(value) > 64:
        raise ValueError("root property array")
    kinds = {"as": "s", "a(ss)": "ss", "a(ssbt)": "ssbt"}[signature]
    if signature == "as":
        return tuple(normal_variant(("s", item), "s") for item in value)
    rows = []
    for row in value:
        if type(row) not in (tuple, list) or len(row) != len(kinds):
            raise ValueError("root property struct")
        rows.append(
            tuple(normal_variant((kind, part), kind) for kind, part in zip(kinds, row))
        )
    return tuple(rows)


def check_properties(variants, plan):
    """Check root-property variants; R4 identity/limits must be checked separately."""
    expected = {
        **root_properties(plan),
        "PrivateUsers": True,
        "ProtectControlGroupsEx": "yes",
    }
    kinds = {**PROPERTY_TYPES, "PrivateUsers": "b", "ProtectControlGroupsEx": "s"}
    runtime._fields(variants, expected)
    for name, value in expected.items():
        if normal_variant(variants[name], kinds[name]) != value:
            raise ValueError("effective root property: " + name)


def lines(data, byte_limit, line_limit):
    if (
        type(data) is not bytes
        or not 0 < len(data) <= byte_limit
        or not data.endswith(b"\n")
    ):
        raise ValueError("incomplete or oversized proc observation")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("non-ASCII proc observation") from error
    if any(ord(char) < 32 and char not in "\t\n" or ord(char) == 127 for char in text):
        raise ValueError("proc observation control byte")
    rows = text.splitlines()
    if len(rows) > line_limit or any(
        not row or "\0" in row or "\r" in row for row in rows
    ):
        raise ValueError("proc observation lines")
    return rows


def decimal(value, maximum=runtime.U64_MAX):
    if re.fullmatch("[0-9]{1,20}", value) is None or int(value) > maximum:
        raise ValueError("proc observation integer")
    return int(value)


def check_id_map(data, selected):
    rows = []
    for line in lines(data, 4096, 16):
        parts = line.split()
        if len(parts) != 3:
            raise ValueError("namespace ID map shape")
        rows.append(tuple(decimal(part, runtime.U32_MAX) for part in parts))
    # systemd v259.10 exec-invoke.c: unprivileged managers omit the root map.
    if rows != [(selected, selected, 1)]:
        raise ValueError("namespace ID map is not self")


def check_status(data, uid, gid):
    rows = {}
    for line in lines(data, 65536, 1024):
        key, separator, value = line.partition(":")
        if not separator or not key or key in rows:
            raise ValueError("process status duplicate or malformed field")
        rows[key] = value.split()
    expected = {
        # PrivatePIDs=yes: the namespace init, with no visible parent or host PID.
        "Pid": ["1"],
        "PPid": ["0"],
        "NSpid": ["1"],
        "Uid": [str(uid)] * 4,
        "Gid": [str(gid)] * 4,
        "Threads": ["1"],
        "NoNewPrivs": ["1"],
        # Filter mode: systemd skips RestrictNamespaces= without seccomp.
        "Seccomp": ["2"],
    }
    expected.update(
        {
            key: ["0000000000000000"]
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        }
    )
    if any(rows.get(key) != value for key, value in expected.items()):
        raise ValueError("process status identity, capabilities or threads")


def mount_path(value):
    # proc_pid_mountinfo(5): only these four octal escapes are produced.
    value = re.sub(r"\\(040|011|012|134)", lambda m: chr(int(m[1], 8)), value)
    if "\\" in value:
        raise ValueError("unsupported mount path escape")
    return value if value == "/" else absolute_path(value)


def mount_options(value):
    parts = value.split(",")
    if any(not part for part in parts) or len(set(parts)) != len(parts):
        raise ValueError("mount options")
    if len(set(parts) & {"ro", "rw"}) != 1:
        raise ValueError("mount permissions")
    return frozenset(parts)


class Mount(NamedTuple):
    """One mountinfo row; the first three fields keep the earlier tuple order."""

    filesystem: str
    options: frozenset
    propagation: tuple
    root: str
    source: str
    super_options: frozenset
    number: int
    parent: int
    device: tuple


def below(path, parent):
    return parent == "/" or nested(path, parent)


def mount_rows(data):
    rows, ids = [], set()
    for line in lines(data, 1024**2, 4096):
        fields = line.split(" ")
        if "" in fields or fields.count("-") != 1:
            raise ValueError("mountinfo separator")
        sep = fields.index("-")
        if sep < 6 or len(fields) != sep + 4:
            raise ValueError("mountinfo shape")
        number, parent = decimal(fields[0]), decimal(fields[1])
        if not number or not parent or number in ids:
            raise ValueError("mountinfo ID")
        ids.add(number)
        device = fields[2].split(":")
        if len(device) != 2:
            raise ValueError("mountinfo device")
        device = tuple(decimal(part, runtime.U32_MAX) for part in device)
        optional = fields[6:sep]
        if any(
            re.fullmatch(r"(?:shared|master|propagate_from):[0-9]+|unbindable", item)
            is None
            for item in optional
        ):
            raise ValueError("mountinfo optional field")
        rows.append(
            (
                mount_path(fields[4]),
                Mount(
                    fields[sep + 1],
                    mount_options(fields[5]),
                    tuple(optional),
                    mount_path(fields[3]),
                    fields[sep + 2],
                    mount_options(fields[-1]),
                    number,
                    parent,
                    device,
                ),
            )
        )
    return rows


def occluded_debugfs(rows):
    """Return the debugfs and tracefs rows the /sys/kernel/debug cover hides.

    The host's tracing automount is a tracefs on its debugfs. G's mount
    namespace copies it locked (fs/namespace.c copy_mnt_ns, lock_mnt_tree),
    and systemd's recursive bind of the debugfs onto G's sysfs keeps the lock
    (copy_tree; v259.10 and v262.1 src/shared/mount-util.c
    bind_mount_submounts). The umount before the cover then fails and is
    ignored (src/core/namespace.c MOUNT_INACCESSIBLE): the tracefs is locked,
    and since Linux 7.2.11 ("namespace: never expire a locked mount") the
    debugfs above it is EBUSY. So the cover lands on the debugfs. Only that
    shape is accepted: one debugfs on /sys, the cover on it as the only other
    mount at its path, at most one tracefs at tracing on the debugfs, nothing
    else below the path or on a hidden row, no propagation tags. With fewer
    than two mounts at the path nothing is hidden there: ((), None).
    """
    at = [mount for path, mount in rows if path == DEBUGFS]
    under = [(path, mount) for path, mount in rows if path.startswith(DEBUGFS + "/")]
    if len(at) < 2:
        return (), None
    paths = {mount.number: path for path, mount in rows}
    if len(at) != 2 or len(under) > 1:
        raise ValueError("occluded debugfs")
    debugfs, cover = sorted(at, key=lambda mount: paths.get(mount.parent) != "/sys")
    hidden = (debugfs, *(mount for _, mount in under))
    numbers = {mount.number for mount in hidden}
    kind = INACCESSIBLE.fullmatch(cover.root)
    if (
        (debugfs.filesystem, debugfs.source, debugfs.root, paths.get(debugfs.parent))
        != ("debugfs", "debugfs", "/", "/sys")
        or cover.parent != debugfs.number
        or cover.filesystem != "tmpfs"
        or kind is None
        or kind[2] != "dir"
        or not SEALED <= cover.options
        or any(
            (path, mount.filesystem, mount.source, mount.root, mount.parent)
            != (TRACING, "tracefs", "tracefs", "/", debugfs.number)
            for path, mount in under
        )
        or any(mount.propagation for mount in (*hidden, cover))
        or any(
            mount.parent in numbers
            for _, mount in rows
            if mount.number not in numbers | {cover.number}
        )
    ):
        raise ValueError("occluded debugfs")
    return hidden, cover


def mount_tree(rows):
    """Return the mount view a path walk reaches; refuse every hidden entry.

    The tree root is the one row whose parent is not listed, at /. A child at
    its parent's own path covers the parent, and a child below a sibling's
    path is occluded by that sibling. Both stack a mount no path walk
    reaches, so either is refused, as is any row the walk never meets. The
    one exception is occluded_debugfs: its rows are dropped and its cover
    takes the debugfs's place in the walk, keeping its own parent field.
    """
    hidden, cover = occluded_debugfs(rows)
    numbers = {mount.number for mount in hidden}
    rows = [row for row in rows if row[1].number not in numbers]
    parents = {mount.number: mount.parent for _, mount in rows}
    if cover is not None:
        parents[cover.number] = hidden[0].parent
    by_id = {mount.number: (path, mount) for path, mount in rows}
    tops = [row for row in rows if parents[row[1].number] not in by_id]
    if len(tops) != 1 or tops[0][0] != "/":
        raise ValueError("mountinfo tree root")
    children = {number: [] for number in by_id}
    for path, mount in rows:
        parent = parents[mount.number]
        if parent in by_id:
            if not below(path, by_id[parent][0]):
                raise ValueError("mountinfo tree")
            children[parent].append((path, mount))
    visible, level = {}, [tops[0]]
    while level:
        following = []
        for path, mount in sorted(level, key=lambda row: row[0]):
            kids = sorted(children[mount.number], key=lambda row: row[0])
            siblings, seen = {kid for kid, _ in kids}, set()
            for kid, _ in kids:
                parts = kid.split("/")
                if (
                    kid == path
                    or kid in seen
                    or any(
                        "/".join(parts[:i]) in siblings for i in range(2, len(parts))
                    )
                ):
                    raise ValueError("stacked mount: " + kid)
                seen.add(kid)
            visible[path] = mount
            following.extend(kids)
        level = following
    if len(visible) != len(rows):
        raise ValueError("mountinfo tree")
    return visible


def parse_mountinfo(data):
    """The reachable mount view; a hidden or unreachable row is refused."""
    return mount_tree(mount_rows(data))


def check_mounts(plan, row):
    mounts = parse_mountinfo(row["mountinfo"])
    for path in DENIAL_NODES:
        if path in mounts and row["denied"][path] is None:
            raise ValueError("mounted denial target reported absent")
    for path in KERNEL_HIDDEN:
        # "-" skips only a missing path (systemd namespace.c, MOUNT_INACCESSIBLE),
        # so every node G can see must carry a cover.
        if (path in mounts) != (row["denied"][path] is not None):
            raise ValueError("kernel cover and node disagree")
    ptmx = row["denied"]["/dev/ptmx"]
    if ptmx is not None and "blocked_by" in ptmx and "/dev/ptmx" in mounts:
        raise ValueError("mount at blocked ptmx symlink")
    readonly = {"/", "/sys", "/sys/fs/cgroup"}
    readonly.update(
        target for _, target, _, _ in root_properties(plan)["BindReadOnlyPaths"]
    )
    required = readonly | {"/proc", "/dev", "/run", "/tmp", ATTEMPT}
    legacy = set(LEGACY_CGROUPS) & mounts.keys()
    allowed = (
        required | set(DENIAL_NODES) | set(DEVICE_BINDS) | legacy | {OS_RELEASE_STAGE}
    )
    if not required <= mounts.keys() or not mounts.keys() <= allowed:
        raise ValueError("missing or unexpected rooted mount")
    # Device binds stay writable: a user manager cannot mknod, so systemd binds
    # the host nodes (namespace.c clone_device_node) and makes only /dev itself
    # read-only, not its submounts (make_read_only).
    readonly |= set(DENIAL_NODES) | legacy | {OS_RELEASE_STAGE, "/dev"}
    types = {
        "/proc": "proc",
        "/dev": "tmpfs",
        "/sys": "sysfs",
        "/sys/fs/cgroup": "cgroup2",
        "/run": "tmpfs",
        "/tmp": "tmpfs",
    }
    for path, mount in mounts.items():
        options = mount.options
        if path in readonly and "ro" not in options:
            raise ValueError("writable protected rooted mount")
        if path in types and mount.filesystem != types[path]:
            raise ValueError("rooted API filesystem type")
        if mount.propagation:
            raise ValueError("rooted mount is not private")
        if (
            path in ("/proc", "/sys", "/sys/fs/cgroup", "/run", "/tmp")
            and not {"nosuid", "nodev", "noexec"} <= options
        ):
            raise ValueError("unsafe rooted API mount flags")
        if path in ("/run", "/tmp", ATTEMPT) and "rw" not in options:
            raise ValueError("rooted writable state unavailable")
    # One fresh proc for G's own PID namespace, mounted on the root. systemd
    # v259.10 drops hidepid= and subset= when its probe finds them unsupported
    # (namespace.c, mount_procfs), so the effective options are pinned here.
    proc = mounts["/proc"]
    if (
        proc.root != "/"
        or proc.parent != mounts["/"].number
        or not {"hidepid=invisible", "subset=pid"} <= proc.super_options
        or sum(mount.filesystem == "proc" for mount in mounts.values()) != 1
        or any(path != "/proc" and nested(path, "/proc") for path in mounts)
    ):
        raise ValueError("rooted proc view")
    covers = set()
    for path in sorted(set(DENIAL_NODES) & mounts.keys()):
        mount = mounts[path]
        match = INACCESSIBLE.fullmatch(mount.root)
        if (
            mount.filesystem != "tmpfs"
            or match is None
            or not SEALED <= mount.options
            or path in KERNEL_HIDDEN
            and match[2] != "dir"
        ):
            raise ValueError("denial is not an inaccessible cover")
        covers.add((mount.device, match[1]))
    if len(covers) > 1:
        raise ValueError("inaccessible covers disagree")
    binds = sorted(set(DEVICE_BINDS) & mounts.keys())
    for path in binds:
        mount = mounts[path]
        if (
            mount.filesystem != "devtmpfs"
            or mount.root != path[len("/dev") :]
            or mount.parent != mounts["/dev"].number
            or "nosuid" not in mount.options
        ):
            raise ValueError("unexpected device bind")
    if len({mounts[path].device for path in binds}) > 1:
        raise ValueError("device binds disagree")
    if len(legacy) > 1:
        raise ValueError("legacy cgroup hierarchy count")
    for path in legacy:
        mount = mounts[path]
        if (
            mount.filesystem != "cgroup"
            or mount.root != "/"
            or mount.parent != mounts["/sys/fs/cgroup"].number
            or not set(path.rpartition("/")[2].split(",")) <= mount.super_options
        ):
            raise ValueError("legacy cgroup hierarchy")
    runtime._fields(row["tmpfs"], ("/run", "/tmp"))
    for path, mode in (("/run", 0o40755), ("/tmp", 0o41777)):
        node = row["tmpfs"][path]
        actual = identity(node, ("mode", "bytes"))
        if (
            actual == identity(plan["host_api"][path])
            or type(node["mode"]) is not int
            or node["mode"] != mode
        ):
            raise ValueError("rooted tmpfs identity or mode")
        runtime._integer(node["bytes"], 16 * 1024**2, 16 * 1024**2)
    entries = row["run_entries"]
    run_allowed = {
        "/run/irlume",
        "/run/host",
        "/run/host/os-release",
        OS_RELEASE_STAGE,
        OS_RELEASE_STAGE + "/os-release",
        "/run/credentials",
        ATTEMPT,
    }
    run_allowed.update(path for path in required if path.startswith("/run/"))
    if (
        type(entries) is not tuple
        or len(entries) > 128
        or any(type(path) is not str for path in entries)
    ):
        raise ValueError("rooted run entry inventory")
    if len(set(entries)) != len(entries) or not set(entries) <= run_allowed:
        raise ValueError("unexpected rooted run entry")
    check_os_release(row["os_release"], mounts, set(entries))


def check_os_release(observed, mounts, entries):
    """Validate systemd259's optional readonly stage and relative symlink."""
    link = "/run/host/os-release"
    staged_file = OS_RELEASE_STAGE + "/os-release"
    paths = {link, OS_RELEASE_STAGE, staged_file}
    if observed is None:
        if paths & (entries | mounts.keys()):
            raise ValueError("unobserved os-release staging")
        return
    runtime._fields(observed, ("link_target", "stage_mode", "file_mode"))
    if (
        observed["link_target"] != ".os-release-stage/os-release"
        or not {"/run/host", link} <= entries
    ):
        raise ValueError("os-release symlink relationship")
    stage_mode, file_mode = observed["stage_mode"], observed["file_mode"]
    if stage_mode is None and file_mode is None:
        if OS_RELEASE_STAGE in mounts or {OS_RELEASE_STAGE, staged_file} & entries:
            raise ValueError("absent os-release staging mismatch")
        return
    for mode in (stage_mode, file_mode):
        runtime._integer(mode, 0, 0o177777)
    if (
        not stat.S_ISDIR(stage_mode)
        or stage_mode & 0o7000
        or not stat.S_ISREG(file_mode)
        or file_mode & 0o7111
    ):
        raise ValueError("os-release staging node types or modes")
    if OS_RELEASE_STAGE not in mounts or not paths <= entries:
        raise ValueError("missing os-release staging mount or entries")


def check_core(plan, row, deadline_ns, now_ns):
    """Check partial kernel evidence, never full readiness or observation origin.

    Denial None values mean observed absence, never an inaccessible ancestor.
    Only the explicit ptmx-to-pts relationship can represent a blocked symlink.
    Full module/native-map checks, API-node and input-bind identity inventories,
    descriptor validity, and a deadline-bounded live collector are still required.
    """
    check_plan(plan)
    runtime._fields(
        row,
        (
            "root",
            "namespaces",
            "uid_map",
            "gid_map",
            "status",
            "fds",
            "denied",
            "dev_log",
            "mountinfo",
            "tmpfs",
            "run_entries",
            "os_release",
            "started_ns",
            "finished_ns",
        ),
    )
    runtime._integer(deadline_ns, 1, runtime.U64_MAX)
    runtime._integer(now_ns, 1, deadline_ns - 1)
    runtime._integer(row["started_ns"], 1, now_ns)
    runtime._integer(
        now_ns, 1, min(deadline_ns, row["started_ns"] + guardian.STOP_NS) - 1
    )
    runtime._integer(
        row["finished_ns"],
        row["started_ns"],
        min(now_ns, row["started_ns"] + guardian.STOP_NS),
    )
    if identity(row["root"]) != identity(plan["root"], ("path",)):
        raise ValueError("root identity mismatch")
    runtime._fields(row["namespaces"], NAMESPACES)
    for name, number in row["namespaces"].items():
        runtime._integer(number, 1, runtime.U64_MAX)
        same = number == plan["host_namespaces"][name]
        if same != (name == "cgroup"):
            raise ValueError("rooted namespace mismatch: " + name)
    check_id_map(row["uid_map"], plan["uid"])
    check_id_map(row["gid_map"], plan["gid"])
    check_status(row["status"], plan["uid"], plan["gid"])
    fds = row["fds"]
    if (
        type(fds) is not tuple
        or len(fds) != 3
        or any(type(fd) is not int for fd in fds)
        or fds != (0, 1, 2)
    ):
        raise ValueError("rooted inherited descriptors")
    runtime._fields(row["denied"], DENIAL_NODES)
    for path, node in row["denied"].items():
        if node is None:
            continue
        blocked = (
            type(node) is dict
            and path == "/dev/ptmx"
            and type(node.get("mode")) is int
            and node["mode"] == stat.S_IFLNK | 0o777
        )
        actual = identity(
            node, ("mode", "target", "blocked_by") if blocked else ("mode",)
        )
        mode = node["mode"]
        if blocked:
            pts = row["denied"]["/dev/pts"]
            if (
                node["target"] != "pts/ptmx"
                or node["blocked_by"] != "/dev/pts"
                or type(pts) is not dict
                or pts.get("mode") != stat.S_IFDIR
            ):
                raise ValueError("unproven ptmx ancestor denial")
        elif type(mode) is not int or mode not in (
            stat.S_IFDIR,
            stat.S_IFREG,
            stat.S_IFCHR,
            stat.S_IFBLK,
            stat.S_IFIFO,
            stat.S_IFSOCK,
        ):
            raise ValueError("readable or unsupported denied node")
        host = plan["host_api"].get(path)
        if host is not None and actual == identity(host):
            raise ValueError("host-backed denied node")
    if row["dev_log"] is not None:
        raise ValueError("unexpected dev log socket")
    check_mounts(plan, row)

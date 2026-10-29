#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Pure rooted-profile checks. No service, mount or VM is created."""

import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


root = load("root", "measurement-job-root.py")
fixtures = load("root_fixtures", "test-measurement-job-closure.py")
guardian_tests = load("root_guardian_tests", "test-measurement-job-guardian.py")
# Literal, not derived from the module constants, so a reorder or drop is caught.
HIDDEN_PROFILE = (
    "-+/dev/pts",
    "-+/dev/ptmx",
    "-+/dev/shm",
    "-+/dev/mqueue",
    "-+/dev/hugepages",
    "-+/sys/fs/selinux",
    "-+/run/credentials",
    "-+/sys/firmware/efi/efivars",
    "-+/sys/fs/bpf",
    "-+/sys/fs/fuse/connections",
    "-+/sys/fs/pstore",
    "-+/sys/fs/smackfs",
    "-+/sys/kernel/config",
    "-+/sys/kernel/debug",
    "-+/sys/kernel/security",
    "-+/sys/kernel/tracing",
)

# Literal: only the selected inputs; G gets no path to the user bus.
INPUT_BINDS = (
    ("/private/base.raw", "/run/irlume/base.raw", False, 0),
    ("/private/payload.raw", "/run/irlume/payload.raw", False, 0),
    ("/private/runtime-manifest.json", "/run/irlume/runtime-manifest.json", False, 0),
)

# Sanitized G mount tables from transient units on a Fedora 44 host (systemd
# 259.10, Linux 7.2.13, a VPN net_cls hierarchy), with plan paths in place of
# host paths.
# PrivatePIDs=no: the host /proc rbind and its binfmt_misc chains.
R5_HOST_PROC = b"""\
1433 1391 0:35 /private/runtime / ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1434 1433 0:81 / /dev ro,nosuid,noexec - tmpfs tmpfs rw,seclabel,size=4096k,nr_inodes=65536,mode=755,uid=1000,gid=1000,inode64
1444 1434 0:7 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1445 1434 0:7 /zero /dev/zero rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1446 1434 0:7 /full /dev/full rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1447 1434 0:7 /random /dev/random rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1448 1434 0:7 /urandom /dev/urandom rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1449 1434 0:7 /tty /dev/tty rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1443 1434 0:84 /systemd/inaccessible/dir /dev/hugepages ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1442 1434 0:84 /systemd/inaccessible/dir /dev/mqueue ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1440 1434 0:84 /systemd/inaccessible/reg /dev/ptmx ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1435 1434 0:84 /systemd/inaccessible/dir /dev/pts ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1441 1434 0:84 /systemd/inaccessible/dir /dev/shm ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1450 1433 0:25 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1451 1450 0:34 / /proc/sys/fs/binfmt_misc rw,relatime - autofs systemd-1 rw,fd=41,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=8874
1452 1451 0:54 / /proc/sys/fs/binfmt_misc rw,nosuid,nodev,noexec,relatime - binfmt_misc binfmt_misc rw
1501 1450 0:25 /acpi /proc/acpi ro,nosuid,nodev,noexec,relatime - proc proc rw
1502 1450 0:25 /asound /proc/asound ro,nosuid,nodev,noexec,relatime - proc proc rw
1503 1450 0:25 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
1504 1450 0:25 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
1505 1450 0:25 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
1506 1450 0:84 /systemd/inaccessible/reg /proc/kallsyms ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1507 1450 0:84 /systemd/inaccessible/reg /proc/kcore ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1508 1450 0:25 /latency_stats /proc/latency_stats ro,nosuid,nodev,noexec,relatime - proc proc rw
1509 1450 0:25 /mtrr /proc/mtrr ro,nosuid,nodev,noexec,relatime - proc proc rw
1510 1450 0:25 /scsi /proc/scsi ro,nosuid,nodev,noexec,relatime - proc proc rw
1511 1450 0:25 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
1512 1511 0:34 / /proc/sys/fs/binfmt_misc rw,relatime - autofs systemd-1 rw,fd=41,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=8874
1513 1512 0:54 / /proc/sys/fs/binfmt_misc ro,nosuid,nodev,noexec,relatime - binfmt_misc binfmt_misc rw
1514 1450 0:25 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
1515 1433 0:35 /private/runtime/root /root rw,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1516 1433 0:87 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,mode=755,uid=1000,gid=1000,inode64
1517 1516 0:84 /systemd/propagate/.os-release-stage /run/host/.os-release-stage ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1518 1516 0:35 /private/attempt /run/irlume/attempt rw,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1519 1516 0:35 /private/base.raw /run/irlume/base.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1520 1516 0:35 /private/payload.raw /run/irlume/payload.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1521 1516 0:35 /private/runtime-manifest.json /run/irlume/runtime-manifest.json ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1522 1516 0:84 /bus /run/user/1000/bus ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1523 1433 0:91 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw,seclabel
1524 1523 0:32 / /sys/firmware/efi/efivars ro,nosuid,nodev,noexec,relatime - efivarfs efivarfs rw
1525 1523 0:33 / /sys/fs/bpf ro,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
1526 1523 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,seclabel,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting
1527 1526 0:85 / /sys/fs/cgroup/net_cls ro,relatime - cgroup net_cls rw,seclabel,net_cls
1528 1523 0:41 / /sys/fs/fuse/connections ro,nosuid,nodev,noexec,relatime - fusectl fusectl rw
1545 1523 0:31 / /sys/fs/pstore ro,nosuid,nodev,noexec,relatime - pstore none rw,seclabel
1547 1523 0:20 / /sys/kernel/config ro,nosuid,nodev,noexec,relatime - configfs configfs rw
1548 1523 0:9 / /sys/kernel/debug ro,nosuid,nodev,noexec,relatime - debugfs debugfs rw,seclabel
1549 1523 0:8 / /sys/kernel/security ro,nosuid,nodev,noexec,relatime - securityfs securityfs rw
1550 1523 0:14 / /sys/kernel/tracing ro,nosuid,nodev,noexec,relatime - tracefs tracefs rw,seclabel
1546 1523 0:84 /systemd/inaccessible/dir /sys/fs/selinux ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1551 1433 0:92 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,uid=1000,gid=1000,inode64
"""
# PrivatePIDs=yes without ProcSubset/ProtectProc: binfmt_misc is re-added.
R5_PID_ONLY = b"""\
1433 1391 0:35 /private/runtime / ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1434 1433 0:81 / /dev ro,nosuid,noexec - tmpfs tmpfs rw,seclabel,size=4096k,nr_inodes=65536,mode=755,uid=1000,gid=1000,inode64
1444 1434 0:7 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1445 1434 0:7 /zero /dev/zero rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1446 1434 0:7 /full /dev/full rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1447 1434 0:7 /random /dev/random rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1448 1434 0:7 /urandom /dev/urandom rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1449 1434 0:7 /tty /dev/tty rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1443 1434 0:84 /systemd/inaccessible/dir /dev/hugepages ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1442 1434 0:84 /systemd/inaccessible/dir /dev/mqueue ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1440 1434 0:84 /systemd/inaccessible/reg /dev/ptmx ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1435 1434 0:84 /systemd/inaccessible/dir /dev/pts ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1441 1434 0:84 /systemd/inaccessible/dir /dev/shm ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1450 1433 0:87 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1451 1450 0:54 / /proc/sys/fs/binfmt_misc rw,nosuid,nodev,noexec,relatime - binfmt_misc binfmt_misc rw
1452 1450 0:87 /acpi /proc/acpi ro,nosuid,nodev,noexec,relatime - proc proc rw
1501 1450 0:87 /asound /proc/asound ro,nosuid,nodev,noexec,relatime - proc proc rw
1502 1450 0:87 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
1503 1450 0:87 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
1504 1450 0:87 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
1505 1450 0:84 /systemd/inaccessible/reg /proc/kallsyms ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1506 1450 0:84 /systemd/inaccessible/reg /proc/kcore ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1507 1450 0:87 /latency_stats /proc/latency_stats ro,nosuid,nodev,noexec,relatime - proc proc rw
1508 1450 0:87 /mtrr /proc/mtrr ro,nosuid,nodev,noexec,relatime - proc proc rw
1509 1450 0:87 /scsi /proc/scsi ro,nosuid,nodev,noexec,relatime - proc proc rw
1510 1450 0:87 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
1511 1510 0:54 / /proc/sys/fs/binfmt_misc ro,nosuid,nodev,noexec,relatime - binfmt_misc binfmt_misc rw
1512 1450 0:87 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
1513 1433 0:35 /private/runtime/root /root rw,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1514 1433 0:91 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,mode=755,uid=1000,gid=1000,inode64
1515 1514 0:84 /systemd/propagate/.os-release-stage /run/host/.os-release-stage ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1516 1514 0:35 /private/attempt /run/irlume/attempt rw,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1517 1514 0:35 /private/base.raw /run/irlume/base.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1518 1514 0:35 /private/payload.raw /run/irlume/payload.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1519 1514 0:35 /private/runtime-manifest.json /run/irlume/runtime-manifest.json ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1520 1514 0:84 /bus /run/user/1000/bus ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1521 1433 0:92 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw,seclabel
1522 1521 0:32 / /sys/firmware/efi/efivars ro,nosuid,nodev,noexec,relatime - efivarfs efivarfs rw
1523 1521 0:33 / /sys/fs/bpf ro,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
1524 1521 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,seclabel,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting
1525 1524 0:85 / /sys/fs/cgroup/net_cls ro,relatime - cgroup net_cls rw,seclabel,net_cls
1526 1521 0:41 / /sys/fs/fuse/connections ro,nosuid,nodev,noexec,relatime - fusectl fusectl rw
1527 1521 0:31 / /sys/fs/pstore ro,nosuid,nodev,noexec,relatime - pstore none rw,seclabel
1545 1521 0:20 / /sys/kernel/config ro,nosuid,nodev,noexec,relatime - configfs configfs rw
1546 1521 0:9 / /sys/kernel/debug ro,nosuid,nodev,noexec,relatime - debugfs debugfs rw,seclabel
1547 1521 0:8 / /sys/kernel/security ro,nosuid,nodev,noexec,relatime - securityfs securityfs rw
1548 1521 0:14 / /sys/kernel/tracing ro,nosuid,nodev,noexec,relatime - tracefs tracefs rw,seclabel
1528 1521 0:84 /systemd/inaccessible/dir /sys/fs/selinux ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1549 1433 0:93 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,uid=1000,gid=1000,inode64
"""
# This series' profile: one fresh subset=pid proc, single covers.
R5_PRIVATE_PIDS = b"""\
1433 1391 0:35 /private/runtime / ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1434 1433 0:81 / /dev ro,nosuid,noexec - tmpfs tmpfs rw,seclabel,size=4096k,nr_inodes=65536,mode=755,uid=1000,gid=1000,inode64
1444 1434 0:7 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1445 1434 0:7 /zero /dev/zero rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1446 1434 0:7 /full /dev/full rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1447 1434 0:7 /random /dev/random rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1448 1434 0:7 /urandom /dev/urandom rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1449 1434 0:7 /tty /dev/tty rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1443 1434 0:84 /systemd/inaccessible/dir /dev/hugepages ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1442 1434 0:84 /systemd/inaccessible/dir /dev/mqueue ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1440 1434 0:84 /systemd/inaccessible/reg /dev/ptmx ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1435 1434 0:84 /systemd/inaccessible/dir /dev/pts ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1441 1434 0:84 /systemd/inaccessible/dir /dev/shm ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1450 1433 0:87 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible,subset=pid
1451 1433 0:91 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,mode=755,uid=1000,gid=1000,inode64
1452 1451 0:84 /systemd/propagate/.os-release-stage /run/host/.os-release-stage ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1501 1451 0:35 /private/attempt /run/irlume/attempt rw,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1502 1451 0:35 /private/base.raw /run/irlume/base.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1503 1451 0:35 /private/payload.raw /run/irlume/payload.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1504 1451 0:35 /private/runtime-manifest.json /run/irlume/runtime-manifest.json ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1505 1451 0:84 /bus /run/user/1000/bus ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1506 1433 0:92 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw,seclabel
1509 1506 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,seclabel,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting
1510 1509 0:85 / /sys/fs/cgroup/net_cls ro,relatime - cgroup net_cls rw,seclabel,net_cls
1507 1506 0:84 /systemd/inaccessible/dir /sys/firmware/efi/efivars ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1508 1506 0:84 /systemd/inaccessible/dir /sys/fs/bpf ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1511 1506 0:84 /systemd/inaccessible/dir /sys/fs/fuse/connections ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1512 1506 0:84 /systemd/inaccessible/dir /sys/fs/pstore ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1513 1506 0:84 /systemd/inaccessible/dir /sys/fs/selinux ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1514 1506 0:84 /systemd/inaccessible/dir /sys/kernel/config ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1515 1506 0:84 /systemd/inaccessible/dir /sys/kernel/debug ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1516 1506 0:84 /systemd/inaccessible/dir /sys/kernel/security ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1517 1506 0:84 /systemd/inaccessible/dir /sys/kernel/tracing ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1518 1433 0:93 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,uid=1000,gid=1000,inode64
"""
# The same table without row 1505, the user-bus bind the profile no longer
# requests.
R5_NO_BUS = b"".join(
    line
    for line in R5_PRIVATE_PIDS.splitlines(keepends=True)
    if b" /run/user/" not in line
)
# Native tables of the bus-free profile. Same host as above, after its debugfs
# tracing automount: the /sys/kernel/debug cover sits on the debugfs and hides
# it and its tracefs (rows 1689, 1690, 1693).
R5_TRACING = b"""\
1660 1522 0:35 /private/runtime / ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1661 1660 0:93 / /dev ro,nosuid,noexec - tmpfs tmpfs rw,seclabel,size=4096k,nr_inodes=65536,mode=755,uid=1000,gid=1000,inode64
1667 1661 0:7 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1668 1661 0:7 /zero /dev/zero rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1669 1661 0:7 /full /dev/full rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1670 1661 0:7 /random /dev/random rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1671 1661 0:7 /urandom /dev/urandom rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1672 1661 0:7 /tty /dev/tty rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1666 1661 0:84 /systemd/inaccessible/dir /dev/hugepages ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1665 1661 0:84 /systemd/inaccessible/dir /dev/mqueue ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1663 1661 0:84 /systemd/inaccessible/reg /dev/ptmx ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1662 1661 0:84 /systemd/inaccessible/dir /dev/pts ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1664 1661 0:84 /systemd/inaccessible/dir /dev/shm ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1673 1660 0:96 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible,subset=pid
1674 1660 0:97 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,mode=755,uid=1000,gid=1000,inode64
1675 1674 0:84 /systemd/propagate/.os-release-stage /run/host/.os-release-stage ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1676 1674 0:35 /private/attempt /run/irlume/attempt rw,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1677 1674 0:35 /private/base.raw /run/irlume/base.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1678 1674 0:35 /private/payload.raw /run/irlume/payload.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1679 1674 0:35 /private/runtime-manifest.json /run/irlume/runtime-manifest.json ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1680 1660 0:98 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw,seclabel
1683 1680 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,seclabel,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting
1684 1683 0:85 / /sys/fs/cgroup/net_cls ro,relatime - cgroup net_cls rw,seclabel,net_cls
1689 1680 0:9 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw,seclabel
1690 1689 0:14 / /sys/kernel/debug/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw,seclabel
1681 1680 0:84 /systemd/inaccessible/dir /sys/firmware/efi/efivars ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1682 1680 0:84 /systemd/inaccessible/dir /sys/fs/bpf ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1685 1680 0:84 /systemd/inaccessible/dir /sys/fs/fuse/connections ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1686 1680 0:84 /systemd/inaccessible/dir /sys/fs/pstore ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1687 1680 0:84 /systemd/inaccessible/dir /sys/fs/selinux ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1688 1680 0:84 /systemd/inaccessible/dir /sys/kernel/config ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1693 1689 0:84 /systemd/inaccessible/dir /sys/kernel/debug ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1691 1680 0:84 /systemd/inaccessible/dir /sys/kernel/security ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1692 1680 0:84 /systemd/inaccessible/dir /sys/kernel/tracing ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1694 1660 0:99 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,uid=1000,gid=1000,inode64
"""
# systemd 262.1, Linux 7.2.11, an ext4 root, no tracing automount: every
# kernel view has a single cover on /sys.
R5_ARCHHOST = b"""\
335 170 259:2 /private/runtime / ro,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
336 335 0:54 / /dev ro,nosuid,noexec - tmpfs tmpfs rw,size=4096k,nr_inodes=65536,mode=755,uid=1000,gid=1000,inode64,huge=advise
342 336 0:7 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw,size=15992344k,nr_inodes=3998086,mode=755,inode64,huge=advise
343 336 0:7 /zero /dev/zero rw,nosuid - devtmpfs devtmpfs rw,size=15992344k,nr_inodes=3998086,mode=755,inode64,huge=advise
344 336 0:7 /full /dev/full rw,nosuid - devtmpfs devtmpfs rw,size=15992344k,nr_inodes=3998086,mode=755,inode64,huge=advise
345 336 0:7 /random /dev/random rw,nosuid - devtmpfs devtmpfs rw,size=15992344k,nr_inodes=3998086,mode=755,inode64,huge=advise
346 336 0:7 /urandom /dev/urandom rw,nosuid - devtmpfs devtmpfs rw,size=15992344k,nr_inodes=3998086,mode=755,inode64,huge=advise
347 336 0:7 /tty /dev/tty rw,nosuid - devtmpfs devtmpfs rw,size=15992344k,nr_inodes=3998086,mode=755,inode64,huge=advise
341 336 0:66 /systemd/inaccessible/dir /dev/hugepages ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
340 336 0:66 /systemd/inaccessible/dir /dev/mqueue ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
338 336 0:66 /systemd/inaccessible/reg /dev/ptmx ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
337 336 0:66 /systemd/inaccessible/dir /dev/pts ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
339 336 0:66 /systemd/inaccessible/dir /dev/shm ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
348 335 0:55 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible,subset=pid
349 335 0:56 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=16384k,nr_inodes=409600,mode=755,uid=1000,gid=1000,inode64,huge=advise
350 349 0:66 /systemd/propagate/.os-release-stage /run/host/.os-release-stage ro,nosuid,nodev,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
351 349 259:2 /private/attempt /run/irlume/attempt rw,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
352 349 259:2 /private/base.raw /run/irlume/base.raw ro,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
353 349 259:2 /private/payload.raw /run/irlume/payload.raw ro,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
373 349 259:2 /private/runtime-manifest.json /run/irlume/runtime-manifest.json ro,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
388 335 0:58 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw
390 388 0:29 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting
392 388 0:66 /systemd/inaccessible/dir /sys/firmware/efi/efivars ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
393 388 0:66 /systemd/inaccessible/dir /sys/fs/bpf ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
397 388 0:66 /systemd/inaccessible/dir /sys/fs/fuse/connections ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
391 388 0:66 /systemd/inaccessible/dir /sys/fs/pstore ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
396 388 0:66 /systemd/inaccessible/dir /sys/kernel/config ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
394 388 0:66 /systemd/inaccessible/dir /sys/kernel/debug ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
389 388 0:66 /systemd/inaccessible/dir /sys/kernel/security ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
395 388 0:66 /systemd/inaccessible/dir /sys/kernel/tracing ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
398 335 0:59 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=16384k,nr_inodes=409600,uid=1000,gid=1000,inode64,huge=advise
"""
# The laptop table above under ProtectControlGroups=strict (2026-10-29 probe):
# the host cgroup2 copy (1895, its root printed upward from G's cgroup
# namespace) and its locked net_cls (1896) stay below a fresh read-only cgroup2
# (1905), next to the debugfs occlusion.
R5_STRICT = b"""\
1786 1402 0:35 /private/runtime / ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1787 1786 0:113 / /dev ro,nosuid,noexec - tmpfs tmpfs rw,seclabel,size=4096k,nr_inodes=65536,mode=755,uid=1000,gid=1000,inode64
1879 1787 0:7 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1880 1787 0:7 /zero /dev/zero rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1881 1787 0:7 /full /dev/full rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1882 1787 0:7 /random /dev/random rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1883 1787 0:7 /urandom /dev/urandom rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1884 1787 0:7 /tty /dev/tty rw,nosuid - devtmpfs devtmpfs rw,seclabel,size=16060992k,nr_inodes=4015248,mode=755,inode64
1878 1787 0:84 /systemd/inaccessible/dir /dev/hugepages ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1877 1787 0:84 /systemd/inaccessible/dir /dev/mqueue ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1875 1787 0:84 /systemd/inaccessible/reg /dev/ptmx ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1788 1787 0:84 /systemd/inaccessible/dir /dev/pts ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1876 1787 0:84 /systemd/inaccessible/dir /dev/shm ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1885 1786 0:114 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible,subset=pid
1886 1786 0:115 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,mode=755,uid=1000,gid=1000,inode64
1887 1886 0:84 /systemd/propagate/.os-release-stage /run/host/.os-release-stage ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1888 1886 0:35 /private/attempt /run/irlume/attempt rw,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1889 1886 0:35 /private/base.raw /run/irlume/base.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1890 1886 0:35 /private/payload.raw /run/irlume/payload.raw ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1891 1886 0:35 /private/runtime-manifest.json /run/irlume/runtime-manifest.json ro,relatime - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,discard=async,space_cache=v2,subvolid=257,subvol=/home
1892 1786 0:116 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw,seclabel
1895 1892 0:30 /../../../../.. /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,seclabel,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting
1896 1895 0:85 / /sys/fs/cgroup/net_cls rw,relatime - cgroup net_cls rw,seclabel,net_cls
1901 1892 0:9 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw,seclabel
1902 1901 0:14 / /sys/kernel/debug/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw,seclabel
1893 1892 0:84 /systemd/inaccessible/dir /sys/firmware/efi/efivars ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1894 1892 0:84 /systemd/inaccessible/dir /sys/fs/bpf ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1905 1895 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,seclabel,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting
1897 1892 0:84 /systemd/inaccessible/dir /sys/fs/fuse/connections ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1898 1892 0:84 /systemd/inaccessible/dir /sys/fs/pstore ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1899 1892 0:84 /systemd/inaccessible/dir /sys/fs/selinux ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1900 1892 0:84 /systemd/inaccessible/dir /sys/kernel/config ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1906 1901 0:84 /systemd/inaccessible/dir /sys/kernel/debug ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1903 1892 0:84 /systemd/inaccessible/dir /sys/kernel/security ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1904 1892 0:84 /systemd/inaccessible/dir /sys/kernel/tracing ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,uid=1000,gid=1000,inode64
1907 1786 0:117 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,seclabel,size=16384k,nr_inodes=409600,uid=1000,gid=1000,inode64
"""
# archhost under ProtectControlGroups=strict (2026-10-29 probe): with no locked
# child systemd unmounts the host copy, so G's cgroup2 (428) is the only
# mount at /sys/fs/cgroup, directly on /sys.
R5_ARCHHOST_STRICT = b"""\
397 70 259:2 /private/runtime / ro,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
398 397 0:56 / /dev ro,nosuid,noexec - tmpfs tmpfs rw,size=4096k,nr_inodes=65536,mode=755,uid=1000,gid=1000,inode64,huge=advise
404 398 0:7 /null /dev/null rw,nosuid - devtmpfs devtmpfs rw,size=15990216k,nr_inodes=3997554,mode=755,inode64,huge=advise
405 398 0:7 /zero /dev/zero rw,nosuid - devtmpfs devtmpfs rw,size=15990216k,nr_inodes=3997554,mode=755,inode64,huge=advise
406 398 0:7 /full /dev/full rw,nosuid - devtmpfs devtmpfs rw,size=15990216k,nr_inodes=3997554,mode=755,inode64,huge=advise
407 398 0:7 /random /dev/random rw,nosuid - devtmpfs devtmpfs rw,size=15990216k,nr_inodes=3997554,mode=755,inode64,huge=advise
408 398 0:7 /urandom /dev/urandom rw,nosuid - devtmpfs devtmpfs rw,size=15990216k,nr_inodes=3997554,mode=755,inode64,huge=advise
409 398 0:7 /tty /dev/tty rw,nosuid - devtmpfs devtmpfs rw,size=15990216k,nr_inodes=3997554,mode=755,inode64,huge=advise
403 398 0:54 /systemd/inaccessible/dir /dev/hugepages ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
402 398 0:54 /systemd/inaccessible/dir /dev/mqueue ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
400 398 0:54 /systemd/inaccessible/reg /dev/ptmx ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
399 398 0:54 /systemd/inaccessible/dir /dev/pts ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
401 398 0:54 /systemd/inaccessible/dir /dev/shm ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
410 397 0:58 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible,subset=pid
411 397 0:59 / /run rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=16384k,nr_inodes=409600,mode=755,uid=1000,gid=1000,inode64,huge=advise
412 411 0:54 /systemd/propagate/.os-release-stage /run/host/.os-release-stage ro,nosuid,nodev,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
413 411 259:2 /private/attempt /run/irlume/attempt rw,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
414 411 259:2 /private/base.raw /run/irlume/base.raw ro,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
415 411 259:2 /private/payload.raw /run/irlume/payload.raw ro,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
417 411 259:2 /private/runtime-manifest.json /run/irlume/runtime-manifest.json ro,nosuid,relatime - ext4 /dev/nvme0n1p2 rw
418 397 0:61 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs rw
422 418 0:54 /systemd/inaccessible/dir /sys/firmware/efi/efivars ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
423 418 0:54 /systemd/inaccessible/dir /sys/fs/bpf ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
428 418 0:29 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting
420 418 0:54 /systemd/inaccessible/dir /sys/fs/fuse/connections ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
421 418 0:54 /systemd/inaccessible/dir /sys/fs/pstore ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
426 418 0:54 /systemd/inaccessible/dir /sys/kernel/config ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
424 418 0:54 /systemd/inaccessible/dir /sys/kernel/debug ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
419 418 0:54 /systemd/inaccessible/dir /sys/kernel/security ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
425 418 0:54 /systemd/inaccessible/dir /sys/kernel/tracing ro,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=3217488k,nr_inodes=804372,mode=700,uid=1000,gid=1000,inode64,huge=advise
427 397 0:66 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=16384k,nr_inodes=409600,uid=1000,gid=1000,inode64,huge=advise
"""


def selection():
    manifest, _ = fixtures.manifest()
    manifest["members"].extend(
        {"path": name, "kind": "directory", "mode": 0o500}
        for name in ("bin", "dev", "etc", "proc", "root", "run", "sys", "tmp", "var")
    )
    manifest["python"]["entry"] = "opt/irlume/measurement-job-guardian-native.py"
    next(m for m in manifest["members"] if m["path"] == "opt/irlume/entry.py")[
        "path"
    ] = manifest["python"]["entry"]
    manifest["members"].sort(key=lambda row: row["path"])
    data = root.closure.canonical(manifest)
    plan = {
        "scope": "contained-job-root-plan-v1",
        "run_id": "run-01",
        "uid": 1000,
        "gid": 1000,
        "root": {"path": "/private/runtime", "device": 1, "inode": 10},
        "attempt": {"path": "/private/attempt", "device": 1, "inode": 11},
        "base": {"path": "/private/base.raw", "device": 1, "inode": 12},
        "payload": {"path": "/private/payload.raw", "device": 1, "inode": 13},
        "manifest": {
            "path": "/private/runtime-manifest.json",
            "device": 1,
            "inode": 14,
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "launcher": {
            "path": "/usr/bin/bootstrap",
            "sha256": next(
                m["sha256"]
                for m in manifest["members"]
                if m["path"] == "usr/bin/bootstrap"
            ),
        },
        "host_namespaces": {
            "pid": 101,
            "user": 102,
            "mnt": 103,
            "net": 104,
            "cgroup": 105,
        },
        "host_api": {
            path: {"device": 2, "inode": 200 + index}
            for index, path in enumerate((*root.DENIED, "/run", "/tmp"))
        },
    }
    return plan, data


# The namespace root's parent lies outside the namespace: never a fixture ID.
OUTSIDE = 1
# The kernel views a typical host has (no smackfs), each under one cover.
HOST_COVERS = tuple(p for p in root.KERNEL_HIDDEN if p != "/sys/fs/smackfs")
COVER_DEVICE = "0:84"


def mount_line(
    number,
    path,
    options="ro,nosuid,nodev,noexec",
    filesystem="tmpfs",
    *,
    parent=OUTSIDE,
    source_root="/",
    super_options="rw",
    device=None,
):
    return (
        f"{number} {parent} {device or f'0:{number}'} {source_root} {path} {options}"
        f" - {filesystem} source {super_options}\n"
    )


def add_mount(data, number, path, *args, **kwargs):
    """Append a mount on the deepest listed mount at or above its path."""
    parent, depth, target = OUTSIDE, -1, root.mount_path(path)
    for line in data.decode().splitlines():
        fields = line.split(" ")
        mounted = root.mount_path(fields[4])
        if mounted != target and root.below(target, mounted) and len(mounted) >= depth:
            parent, depth = int(fields[0]), len(mounted)
    return data + mount_line(number, path, *args, parent=parent, **kwargs).encode()


def add_cover(data, number, path, kind="dir", **kwargs):
    """Append a systemd inaccessible cover in the user manager's runtime dir."""
    return add_mount(
        data,
        number,
        path,
        "ro,nosuid,nodev,noexec,relatime",
        "tmpfs",
        source_root="/systemd/inaccessible/" + kind,
        device=COVER_DEVICE,
        **kwargs,
    )


def witness(plan):
    # The cgroup2 is the strict view on a host without a legacy hierarchy:
    # nothing to keep below it, so it sits on /sys (occluded_cgroup).
    mounts = [
        ("/", "ro", "ext4"),
        ("/proc", "rw,nosuid,nodev,noexec", "proc"),
        ("/dev", "ro,nosuid,noexec", "tmpfs"),
        ("/sys", "ro,nosuid,nodev,noexec", "sysfs"),
        ("/sys/fs/cgroup", "ro,nosuid,nodev,noexec", "cgroup2"),
        ("/run", "rw,nosuid,nodev,noexec", "tmpfs"),
        ("/tmp", "rw,nosuid,nodev,noexec", "tmpfs"),
        (root.ATTEMPT, "rw,nosuid,nodev,noexec", "ext4"),
    ]
    mounts += [
        (p, "ro,nosuid,nodev,noexec", "ext4")
        for p in (
            "/run/irlume/base.raw",
            "/run/irlume/payload.raw",
            "/run/irlume/runtime-manifest.json",
        )
    ]
    mountinfo = b""
    for i, (path, options, filesystem) in enumerate(mounts):
        proc = {"super_options": "rw,hidepid=invisible,subset=pid"}
        mountinfo = add_mount(
            mountinfo,
            i + 2,
            path,
            options,
            filesystem,
            **(proc if path == "/proc" else {}),
        )
    # A user manager cannot mknod: the minimal nodes are rw,nosuid host binds.
    for i, path in enumerate(root.DEVICE_BINDS):
        mountinfo = add_mount(
            mountinfo,
            20 + i,
            path,
            "rw,nosuid",
            "devtmpfs",
            source_root=path[len("/dev") :],
            device="0:7",
        )
    denied = dict.fromkeys(root.DENIAL_NODES)
    for i, path in enumerate(HOST_COVERS):
        mountinfo = add_cover(mountinfo, 30 + i, path)
        denied[path] = {"device": 3, "inode": 600 + i, "mode": 0o40000}
    return {
        "root": {"device": 1, "inode": 10},
        "namespaces": {"pid": 201, "user": 202, "mnt": 203, "net": 204, "cgroup": 205},
        "uid_map": b"      1000       1000          1\n",
        "gid_map": b"      1000       1000          1\n",
        "status": b"Name:\tpython3\nPid:\t1\nPPid:\t0\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nNStgid:\t1\nNSpid:\t1\nThreads:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n",
        "fds": (0, 1, 2),
        "denied": denied,
        "dev_log": None,
        "mountinfo": mountinfo,
        "tmpfs": {
            path: {"device": 4, "inode": i + 500, "mode": mode, "bytes": 16 * 1024**2}
            for i, (path, mode) in enumerate((("/run", 0o40755), ("/tmp", 0o41777)))
        },
        "run_entries": (
            "/run/irlume",
            root.ATTEMPT,
            "/run/irlume/base.raw",
            "/run/irlume/payload.raw",
            "/run/irlume/runtime-manifest.json",
        ),
        "os_release": None,
        "started_ns": 100,
        "finished_ns": 200,
    }


def native_row(plan, data):
    """A witness row whose denial nodes and os-release staging match a table."""
    row = witness(plan)
    view = root.parse_mountinfo(data)
    for i, path in enumerate(root.DENIAL_NODES):
        mode = 0o100000 if path == "/dev/ptmx" else 0o40000
        node = {"device": 3, "inode": 700 + i, "mode": mode}
        row["denied"][path] = node if path in view else None
    stage = root.OS_RELEASE_STAGE
    row["run_entries"] += ("/run/host", "/run/host/os-release", stage)
    row["run_entries"] += (stage + "/os-release",)
    row["os_release"] = {
        "link_target": ".os-release-stage/os-release",
        "stage_mode": 0o40755,
        "file_mode": 0o100644,
    }
    row["mountinfo"] = data
    return row


class ProfileTests(unittest.TestCase):
    def test_plan_scope_is_checked_without_object_equality(self):
        class Scope:
            def __eq__(self, other):
                raise AssertionError("untrusted scope equality")

        plan, _ = selection()
        plan["scope"] = Scope()
        with self.assertRaises(ValueError):
            root.check_plan(plan)

    def test_root_properties_roundtrip_real_wire_without_connecting_to_a_bus(self):
        import jeepney

        self.assertEqual(jeepney.__version__, "0.9.0")
        plan, _ = selection()
        entries = root.wire_properties(plan)
        address = jeepney.DBusAddress(
            "/org/freedesktop/systemd1",
            bus_name="org.freedesktop.systemd1",
            interface="org.freedesktop.systemd1.Manager",
        )
        message = jeepney.new_method_call(
            address,
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            ("test.service", "fail", entries, []),
        )
        wire = message.serialise(serial=1)
        parser = jeepney.Parser()
        for offset in range(0, len(wire), 7):
            parser.add_data(wire[offset : offset + 7])
        decoded = parser.get_next_message()
        self.assertIsNotNone(decoded)
        observed = dict(decoded.body[2])
        self.assertEqual(observed["ProtectControlGroupsEx"], ("s", "strict"))
        self.assertNotIn("ProtectControlGroups", observed)
        observed.update(PrivateUsers=("b", True), ProtectControlGroups=("b", True))
        self.assertIsNone(root.check_properties(observed, plan))
        self.assertIsNone(parser.get_next_message())

    def test_fixed_inert_profile_preserves_limits_and_omits_kvm(self):
        plan, data = selection()
        spec = root.guardian.Specification(**guardian_tests.specification()._asdict())
        props = root.service_properties(spec, plan, data)
        for key, value in root.guardian.service_properties(spec).items():
            self.assertEqual(props[key], value)
        self.assertEqual(props["PrivateUsersEx"], "self")
        self.assertEqual(
            (props["PrivatePIDs"], props["ProcSubset"], props["ProtectProc"]),
            ("yes", "pid", "invisible"),
        )
        # G's own cgroup namespace and a fresh read-only cgroup2 of it.
        self.assertEqual(props["ProtectControlGroupsEx"], "strict")
        self.assertNotIn("ProtectControlGroups", props)
        self.assertIs(props["BindLogSockets"], False)
        self.assertEqual(props["DeviceAllow"], ())
        self.assertEqual(
            props["BindPaths"], (("/private/attempt", "/run/irlume/attempt", False, 0),)
        )
        self.assertEqual(props["InaccessiblePaths"], HIDDEN_PROFILE)
        self.assertFalse(
            any(p.startswith("-+/proc/") for p in props["InaccessiblePaths"])
        )
        self.assertEqual(props["ProtectHome"], "read-only")
        self.assertIs(props["ProtectKernelLogs"], True)
        self.assertEqual(
            (type(props["RestrictNamespaces"]), props["RestrictNamespaces"]), (int, 0)
        )
        # A user manager's services share its session keyring by default.
        self.assertEqual(props["KeyringMode"], "private")
        self.assertEqual(
            root.entry_argv(plan, "c" * 64),
            (
                "/usr/bin/bootstrap",
                "--guardian",
                "/run/irlume/attempt/guardian-config.json",
                "c" * 64,
            ),
        )

    def test_profile_binds_no_user_bus(self):
        plan, data = selection()
        spec = root.guardian.Specification(**guardian_tests.specification()._asdict())
        props = root.service_properties(spec, plan, data)
        self.assertEqual(props["BindReadOnlyPaths"], INPUT_BINDS)
        for name in ("BindPaths", "BindReadOnlyPaths"):
            for source, target, _, _ in props[name]:
                with self.subTest(name=name, target=target):
                    self.assertFalse(source.startswith("/run/user"))
                    self.assertFalse(target.startswith("/run/user"))
        self.assertNotIn("/run/user", repr(root.wire_properties(plan)))

    def test_check_properties_refuses_user_bus_bind(self):
        plan, _ = selection()
        variants = {
            key: (root.PROPERTY_TYPES[key], value)
            for key, value in root.root_properties(plan).items()
        }
        variants.update(PrivateUsers=("b", True), ProtectControlGroups=("b", True))
        variants["BindReadOnlyPaths"] = ("a(ssbt)", INPUT_BINDS)
        self.assertIsNone(root.check_properties(variants, plan))
        bus = f"/run/user/{plan['uid']}/bus"
        variants["BindReadOnlyPaths"] = (
            "a(ssbt)",
            (*INPUT_BINDS, (bus, bus, False, 0)),
        )
        with self.assertRaisesRegex(
            ValueError, "^effective root property: BindReadOnlyPaths$"
        ):
            root.check_properties(variants, plan)

    def test_plan_rejects_aliases_overlap_bad_types_and_unknown_fields(self):
        plan, _ = selection()
        for key, value in (("uid", True), ("gid", 0), ("extra", 1), ("scope", "v1")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                root.check_plan(dict(plan, **{key: value}))
        for path in (
            "/",
            "/private//base",
            "/private/../base",
            "/private/./base",
            "/bad\npath",
            "/a/",
            "/é",
        ):
            bad = copy.deepcopy(plan)
            bad["base"]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                root.check_plan(bad)
        for key in ("base", "payload", "manifest", "root"):
            bad = copy.deepcopy(plan)
            bad[key]["path"] = plan["attempt"]["path"] + "/nested"
            with self.subTest(key=key), self.assertRaises(ValueError):
                root.check_plan(bad)
        bad = copy.deepcopy(plan)
        bad["base"]["inode"] = plan["payload"]["inode"]
        with self.assertRaises(ValueError):
            root.check_plan(bad)

    def test_selection_must_bind_fixed_entry_bootstrap_hash_and_no_api_code(self):
        plan, data = selection()
        root.check_selection(plan, data)
        for mutate in (
            lambda m: m["python"].update(entry="usr/bin/bootstrap"),
            lambda m: m.update(bootstrap="usr/bin/python3"),
            lambda m: m["members"].append(
                {"path": "run", "kind": "directory", "mode": 0o500}
            ),
        ):
            manifest = root.closure.decode_manifest(data, plan["manifest"]["sha256"])
            mutate(manifest)
            manifest["members"].sort(key=lambda row: row["path"])
            changed = root.closure.canonical(manifest)
            bad = copy.deepcopy(plan)
            bad["manifest"]["sha256"] = hashlib.sha256(changed).hexdigest()
            with self.assertRaises(ValueError):
                root.check_selection(bad, changed)
        with self.assertRaises(ValueError):
            root.check_selection(plan, data + b" ")

    def test_typed_readback_rejects_coercion_missing_and_unsafe_values(self):
        plan, _ = selection()
        variants = {
            key: (root.PROPERTY_TYPES[key], value)
            for key, value in root.root_properties(plan).items()
        }
        variants.update(PrivateUsers=("b", True), ProtectControlGroups=("b", True))
        self.assertIsNone(root.check_properties(variants, plan))
        for key in variants:
            bad = dict(variants)
            del bad[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                root.check_properties(bad, plan)
        for key, value in (
            ("PrivatePIDs", ("b", False)),
            ("PrivateUsers", ("b", 1)),
            ("PrivateUsersEx", ("s", "identity")),
            ("PrivateNetwork", ("b", False)),
            ("CapabilityBoundingSet", ("t", False)),
            ("ProtectControlGroupsEx", ("s", "yes")),
            ("ProtectControlGroups", ("b", False)),
            ("BindLogSockets", ("b", True)),
            ("InaccessiblePaths", ("as", tuple("-" + p for p in root.DENIED))),
            ("InaccessiblePaths", ("as", root.DENIED)),
            (
                "BindPaths",
                ("a(ssbt)", (("/private/attempt", root.ATTEMPT, False, True),)),
            ),
            ("BindPaths", ("a(ssbt)", (("/private/attempt", root.ATTEMPT, True, 0),))),
            (
                "BindPaths",
                ("a(ssbt)", (("/private/attempt", root.ATTEMPT, False, 16384),)),
            ),
            ("DeviceAllow", ("a(ss)", (("/dev/kvm", "rw"),))),
            ("TemporaryFileSystem", ("a(ss)", (("/tmp", "rw"),))),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                root.check_properties(dict(variants, **{key: value}), plan)
        # The earlier layout also listed /proc/sys/fs, absent under ProcSubset=pid.
        sysctl = (*HIDDEN_PROFILE[:7], "-+/proc/sys/fs", *HIDDEN_PROFILE[7:])
        swapped = (*HIDDEN_PROFILE[:7], HIDDEN_PROFILE[8], HIDDEN_PROFILE[7])
        swapped += HIDDEN_PROFILE[9:]
        unrooted = tuple(
            "-/sys/kernel/debug" if p == "-+/sys/kernel/debug" else p
            for p in HIDDEN_PROFILE
        )
        for key, value, message in (
            ("PrivatePIDs", ("s", "no"), "effective root property: PrivatePIDs"),
            ("ProcSubset", ("s", "all"), "effective root property: ProcSubset"),
            ("ProcSubset", ("b", True), "root property signature"),
            *(
                ("ProtectProc", ("s", mode), "effective root property: ProtectProc")
                for mode in ("default", "noaccess", "ptraceable")
            ),
            ("ProtectHome", ("s", "no"), "effective root property: ProtectHome"),
            ("ProtectHome", ("s", "yes"), "effective root property: ProtectHome"),
            ("ProtectHome", ("s", "tmpfs"), "effective root property: ProtectHome"),
            ("ProtectHome", ("b", True), "root property signature"),
            *(
                ("KeyringMode", ("s", mode), "effective root property: KeyringMode")
                for mode in ("inherit", "shared")
            ),
            ("KeyringMode", ("b", True), "root property signature"),
            # yes keeps the host tree and namespace, private a writable one,
            # no the host tree writable.
            *(
                (
                    "ProtectControlGroupsEx",
                    ("s", mode),
                    "effective root property: ProtectControlGroupsEx",
                )
                for mode in ("yes", "private", "no", "true")
            ),
            ("ProtectControlGroupsEx", ("b", True), "root property signature"),
            (
                "ProtectControlGroups",
                ("b", False),
                "effective root property: ProtectControlGroups",
            ),
            ("ProtectControlGroups", ("s", "strict"), "root property signature"),
            (
                "ProtectKernelLogs",
                ("b", False),
                "effective root property: ProtectKernelLogs",
            ),
            (
                "RestrictNamespaces",
                ("t", 2**64 - 1),
                "effective root property: RestrictNamespaces",
            ),
            (
                "RestrictNamespaces",
                ("t", 0x10000000),
                "effective root property: RestrictNamespaces",
            ),
            ("RestrictNamespaces", ("b", True), "root property signature"),
            *(
                (
                    "InaccessiblePaths",
                    ("as", paths),
                    "effective root property: InaccessiblePaths",
                )
                for paths in (HIDDEN_PROFILE[:7], sysctl, swapped, unrooted)
            ),
        ):
            with (
                self.subTest(key=key, value=value),
                self.assertRaisesRegex(ValueError, message),
            ):
                root.check_properties(dict(variants, **{key: value}), plan)

    def test_selection_rejects_internally_valid_but_unselected_entries(self):
        for change in ("entry", "bootstrap-path", "bootstrap-digest"):
            plan, data = selection()
            manifest = root.closure.decode_manifest(data, plan["manifest"]["sha256"])
            if change == "entry":
                for member in manifest["members"]:
                    if member["path"] == manifest["python"]["entry"]:
                        member["path"] = "opt/irlume/other.py"
                manifest["python"]["entry"] = "opt/irlume/other.py"
            elif change == "bootstrap-path":
                manifest["bootstrap"] = "usr/bin/python3"
                plan["launcher"]["sha256"] = next(
                    m["sha256"]
                    for m in manifest["members"]
                    if m["path"] == "usr/bin/python3"
                )
            else:
                plan["launcher"]["sha256"] = "f" * 64
            manifest["members"].sort(key=lambda row: row["path"])
            data = root.closure.canonical(manifest)
            plan["manifest"]["sha256"] = hashlib.sha256(data).hexdigest()
            # Establish that it is valid closure metadata, not an earlier parser failure.
            root.closure.decode_manifest(data, plan["manifest"]["sha256"])
            with self.subTest(change=change), self.assertRaises(ValueError):
                root.check_selection(plan, data)

    def test_root_profile_cannot_switch_the_selected_transaction(self):
        plan, data = selection()
        spec = root.guardian.Specification(
            **guardian_tests.specification(run_id="other")._asdict()
        )
        with self.assertRaises(ValueError):
            root.service_properties(spec, plan, data)


class ReviewCorrectionsTests(unittest.TestCase):
    def test_systemd_os_release_staging_mount_and_symlink_match_source(self):
        plan, _ = selection()
        row = witness(plan)
        stage = "/run/host/.os-release-stage"
        row["run_entries"] += (
            "/run/host",
            stage,
            stage + "/os-release",
            "/run/host/os-release",
        )
        row["mountinfo"] = add_mount(row["mountinfo"], 40, stage)
        row["os_release"] = {
            "link_target": ".os-release-stage/os-release",
            "stage_mode": 0o40755,
            "file_mode": 0o100644,
        }
        self.assertIsNone(root.check_mounts(plan, row))
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        for changes in (
            {
                "mountinfo": row["mountinfo"].replace(
                    (stage + " ro").encode(), (stage + " rw").encode()
                )
            },
            {"run_entries": (*row["run_entries"], stage + "/extra")},
            {"os_release": {**row["os_release"], "link_target": "/etc/os-release"}},
            {"os_release": {**row["os_release"], "stage_mode": 0o100644}},
            {"os_release": {**row["os_release"], "file_mode": 0o120777}},
            {"os_release": {**row["os_release"], "file_mode": 0o100755}},
            {
                "os_release": {
                    **row["os_release"],
                    "stage_mode": None,
                    "file_mode": None,
                }
            },
            {
                "mountinfo": b"\n".join(
                    line
                    for line in row["mountinfo"].splitlines()
                    if stage.encode() not in line
                )
                + b"\n"
            },
            {
                "run_entries": tuple(
                    path for path in row["run_entries"] if path != stage + "/os-release"
                )
            },
            {"os_release": None},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, **changes), 1000, 250)

    def test_optional_os_release_missing_stage_keeps_only_the_dangling_link(self):
        plan, _ = selection()
        row = witness(plan)
        row["run_entries"] += ("/run/host", "/run/host/os-release")
        row["os_release"] = {
            "link_target": ".os-release-stage/os-release",
            "stage_mode": None,
            "file_mode": None,
        }
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        with self.assertRaisesRegex(ValueError, "missing or unexpected rooted mount"):
            root.check_core(
                plan,
                dict(
                    row,
                    mountinfo=add_mount(row["mountinfo"], 40, "/run/host/os-release"),
                ),
                1000,
                250,
            )

    def test_user_manager_maps_only_the_callers_selected_identity(self):
        self.assertIsNone(root.check_id_map(b"1000 1000 1\n", 1000))
        self.assertIsNone(root.check_id_map(b"1001 1001 1\n", 1001))
        with self.assertRaises(ValueError):
            root.check_id_map(b"0 0 1\n1000 1000 1\n", 1000)

    def test_private_propagation_is_explicit_and_typed(self):
        plan, _ = selection()
        self.assertEqual(root.root_properties(plan).get("MountFlags"), 1 << 18)
        variants = dict(root.wire_properties(plan))
        self.assertEqual(variants.get("MountFlags"), ("t", 1 << 18))
        variants.update(PrivateUsers=("b", True), ProtectControlGroups=("b", True))
        for invalid in (("s", "private"), ("t", True), ("t", 0), ("t", 1 << 20)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                root.check_properties(dict(variants, MountFlags=invalid), plan)

    def test_mount_at_denial_target_cannot_also_be_reported_absent(self):
        plan, _ = selection()
        row = witness(plan)
        for path in ("/dev/shm", "/dev/pts", "/run/credentials"):
            self.assertIsNone(row["denied"][path])
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ValueError, "denial target reported absent"),
            ):
                root.check_core(
                    plan,
                    dict(row, mountinfo=add_mount(row["mountinfo"], 40, path)),
                    1000,
                    250,
                )

    def test_private_propagation_rejects_slave_and_shared_effective_tags(self):
        plan, _ = selection()
        row = witness(plan)
        for tag in ("shared:42", "master:42", "propagate_from:42", "unbindable"):
            changed = row["mountinfo"].replace(
                b" - sysfs ", f" {tag} - sysfs ".encode()
            )
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, mountinfo=changed), 1000, 250)

    def test_inaccessible_ancestor_is_not_silently_converted_to_absence(self):
        plan, _ = selection()
        row = witness(plan)
        row["denied"]["/dev/ptmx"] = {"blocked_by": "/dev/pts"}
        with self.assertRaises(ValueError):
            root.check_core(plan, row, 1000, 250)


class ParserTests(unittest.TestCase):
    def test_exact_maps_allow_distinct_uid_gid_but_no_broad_mapping(self):
        self.assertIsNone(root.check_id_map(b"1001 1001 1\n", 1001))
        for data in (
            b"1001 1001 2\n",
            b"1001 1001 1",
            b"1001 1001 1\r\n",
            b"+1001 1001 1\n",
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                root.check_id_map(data, 1001)

    def test_mountinfo_parses_escaped_spaces_but_rejects_truncation_and_aliases(self):
        data = add_mount(mount_line(2, "/").encode(), 3, r"/some\040path")
        self.assertIn("/some path", root.parse_mountinfo(data))
        for data in (
            mount_line(1, "/").encode() * 2,
            mount_line(1, "/", "ro,rw").encode(),
            mount_line(1, "/").replace("0:1", "0:bad").encode(),
            mount_line(1, "/").replace("ro,nosuid", "ro,ro,nosuid").encode(),
            mount_line(1, "/").encode().rstrip(b"\n"),
        ):
            with self.subTest(data=data), self.assertRaises(ValueError):
                root.parse_mountinfo(data)

    def test_upward_root_is_parsed_only_for_cgroup2_rows(self):
        def row(mount_root, filesystem="cgroup2"):
            return mount_line(
                3, "/sys/fs/cgroup", "rw", filesystem, parent=2, source_root=mount_root
            ).encode()

        # cgroup_show_path prints a host cgroup2 root relative to the reader's
        # cgroup namespace: one /.. per level up to the common ancestor.
        for levels in (1, 5, 64):
            with self.subTest(levels=levels):
                [(path, mount)] = root.mount_rows(row("/.." * levels))
                self.assertEqual((path, mount.root), ("/sys/fs/cgroup", "/.." * levels))
        # Names that only start with dots are plain roots.
        for mount_root in ("/..x", "/..."):
            with self.subTest(mount_root=mount_root):
                [(_, mount)] = root.mount_rows(row(mount_root))
                self.assertIsNone(root.UPWARD.fullmatch(mount.root))
        for mount_root in (
            "/.." * 65,
            "/../x",
            "/../",
            "/.../..",
            "/..//..",
            "/./..",
            "..",
            r"/\056\056",
        ):
            with (
                self.subTest(mount_root=mount_root),
                self.assertRaises(ValueError),
            ):
                root.mount_rows(row(mount_root))
        for filesystem in ("cgroup", "tmpfs", "sysfs", "cgroup2x"):
            with (
                self.subTest(filesystem=filesystem),
                self.assertRaisesRegex(ValueError, "^runtime member path$"),
            ):
                root.mount_rows(row("/..", filesystem))

    def test_visible_upward_root_is_refused(self):
        top = mount_line(2, "/").encode()
        sysfs = add_mount(top, 3, "/sys", "ro,nosuid,nodev,noexec", "sysfs")
        for mount_root in ("/", "/x"):
            data = add_mount(
                sysfs, 4, "/sys/fs/cgroup", "ro", "cgroup2", source_root=mount_root
            )
            self.assertEqual(
                root.parse_mountinfo(data)["/sys/fs/cgroup"].root, mount_root
            )
        # The host tree seen from another cgroup namespace, with no fresh
        # cgroup2 above it: systemd's privilege fallback keeps it visible.
        for levels in (1, 5):
            data = add_mount(
                sysfs, 4, "/sys/fs/cgroup", "ro", "cgroup2", source_root="/.." * levels
            )
            with (
                self.subTest(levels=levels),
                self.assertRaisesRegex(ValueError, "^upward mount root$"),
            ):
                root.parse_mountinfo(data)

    def test_mount_tree_keeps_the_walkable_view(self):
        top = mount_line(2, "/").encode()
        self.assertEqual(set(root.parse_mountinfo(top)), {"/"})
        data = add_mount(add_mount(top, 3, "/run"), 4, root.ATTEMPT)
        view = root.parse_mountinfo(data)
        self.assertEqual(set(view), {"/", "/run", root.ATTEMPT})
        self.assertEqual(view[root.ATTEMPT].parent, view["/run"].number)
        self.assertEqual(view["/run"].parent, view["/"].number)
        # Index access keeps the earlier (filesystem, options, propagation) order.
        row = view["/run"]
        self.assertEqual(row[:3], (row.filesystem, row.options, row.propagation))
        self.assertEqual(
            (row.root, row.source, row.super_options, row.device),
            ("/", "source", frozenset({"rw"}), (0, 3)),
        )

    def test_mount_tree_refuses_roots_cycles_and_hidden_entries(self):
        top = mount_line(2, "/")

        def rows(*items):
            return "".join(
                mount_line(number, path, parent=parent)
                for number, parent, path in items
            )

        for label, data, message in (
            ("no root", rows((2, 3, "/"), (3, 2, "/x")), "mountinfo tree root"),
            ("two roots", rows((2, 1, "/"), (3, 1, "/tmp")), "mountinfo tree root"),
            ("root not at /", rows((2, 1, "/tmp")), "mountinfo tree root"),
            ("self parent", rows((2, 2, "/")), "mountinfo tree root"),
            (
                "outside parent",
                top + rows((3, 2, "/run"), (4, 3, "/tmp/x")),
                "^mountinfo tree$",
            ),
            (
                "unreached cycle",
                top + rows((3, 4, "/a"), (4, 3, "/a")),
                "^mountinfo tree$",
            ),
            (
                "duplicate sibling",
                top + rows((3, 2, "/tmp"), (4, 2, "/tmp")),
                "^stacked mount: /tmp$",
            ),
            ("cover over /", top + rows((3, 2, "/")), "^stacked mount: /$"),
            (
                "tmpfs on /tmp",
                top + rows((3, 2, "/tmp"), (4, 3, "/tmp")),
                "^stacked mount: /tmp$",
            ),
            (
                "occluded",
                top + rows((3, 2, "/proc"), (4, 3, "/proc/sys"), (5, 3, "/proc/sys/x")),
                "^stacked mount: /proc/sys/x$",
            ),
        ):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, message),
            ):
                root.parse_mountinfo(data.encode())

    def test_real_tables_refuse_hidden_binfmt_and_keep_the_private_view(self):
        for data in (R5_HOST_PROC, R5_PID_ONLY):
            with self.assertRaisesRegex(
                ValueError, "^stacked mount: /proc/sys/fs/binfmt_misc$"
            ):
                root.parse_mountinfo(data)
        view = root.parse_mountinfo(R5_PRIVATE_PIDS)
        self.assertEqual(len(view), R5_PRIVATE_PIDS.count(b"\n"))
        proc = view["/proc"]
        self.assertEqual(
            (proc.filesystem, proc.root, proc.parent),
            ("proc", "/", view["/"].number),
        )
        self.assertLessEqual({"hidepid=invisible", "subset=pid"}, proc.super_options)
        self.assertFalse(any(p != "/proc" and root.nested(p, "/proc") for p in view))

    def test_debug_cover_stacked_on_the_debugfs_hides_only_debugfs_and_tracefs(self):
        view = root.parse_mountinfo(R5_TRACING)
        self.assertEqual(len(view), R5_TRACING.count(b"\n") - 2)
        cover = view["/sys/kernel/debug"]
        self.assertEqual(
            (cover.filesystem, cover.root, cover.number, cover.parent),
            ("tmpfs", "/systemd/inaccessible/dir", 1693, 1689),
        )
        self.assertNotIn(1689, {mount.number for mount in view.values()})
        self.assertNotIn("/sys/kernel/debug/tracing", view)
        # Untriggered, the cover is a single mount on /sys.
        view = root.parse_mountinfo(R5_ARCHHOST)
        self.assertEqual(len(view), R5_ARCHHOST.count(b"\n"))
        self.assertEqual(view["/sys/kernel/debug"].parent, view["/sys"].number)

    def test_property_wire_types_reject_malformed_structs_and_integer_ranges(self):
        for variant, kind in (
            (("as", "wrong"), "as"),
            (("a(ss)", [("one",)]), "a(ss)"),
            (("a(ssbt)", [("a", "b", 0, 0)]), "a(ssbt)"),
            (("t", -1), "t"),
            (("t", 2**64), "t"),
            (("s", "a\0b"), "s"),
            (("as", ["a"] * 65), "as"),
            (("s", "a" * 4097), "s"),
        ):
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                root.normal_variant(variant, kind)


class CoreTests(unittest.TestCase):
    def test_denial_fallbacks_and_explicit_ptmx_ancestor_are_checked(self):
        plan, _ = selection()
        for mode in (0o10000, 0o60000, 0o140000):
            row = witness(plan)
            row["denied"]["/proc/kcore"] = {"device": 3, "inode": 501, "mode": mode}
            self.assertIsNone(root.check_core(plan, row, 1000, 250))
        row = witness(plan)
        row["denied"]["/dev/pts"] = {"device": 3, "inode": 502, "mode": 0o40000}
        row["denied"]["/dev/ptmx"] = {
            "device": 3,
            "inode": 503,
            "mode": 0o120777,
            "target": "pts/ptmx",
            "blocked_by": "/dev/pts",
        }
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        for change, message in (
            ("missing-parent", "unproven ptmx ancestor denial"),
            ("readable-parent", "readable or unsupported denied node"),
            ("wrong-target", "unproven ptmx ancestor denial"),
            ("host-link", "host-backed denied node"),
            ("link-mount", "mount at blocked ptmx symlink"),
        ):
            bad = copy.deepcopy(row)
            if change == "missing-parent":
                bad["denied"]["/dev/pts"] = None
            elif change == "readable-parent":
                bad["denied"]["/dev/pts"]["mode"] |= 0o700
            elif change == "wrong-target":
                bad["denied"]["/dev/ptmx"]["target"] = "/outside"
            elif change == "host-link":
                bad["denied"]["/dev/ptmx"].update(plan["host_api"]["/dev/ptmx"])
            else:
                bad["mountinfo"] = add_mount(bad["mountinfo"], 90, "/dev/ptmx")
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, message),
            ):
                root.check_core(plan, bad, 1000, 250)

    def test_proc_is_one_fresh_subset_pid_instance(self):
        plan, _ = selection()
        row = witness(plan)
        line = next(x for x in row["mountinfo"].splitlines() if b" /proc " in x)
        self.assertTrue(line.endswith(b" rw,hidepid=invisible,subset=pid"))
        changes = {
            "host instance": line.replace(b",hidepid=invisible,subset=pid", b""),
            "no subset": line.replace(b",subset=pid", b""),
            "no hidepid": line.replace(b"hidepid=invisible,", b""),
            "ptraceable": line.replace(b"=invisible", b"=ptraceable"),
            "subdirectory": line.replace(b" / /proc ", b" /sys /proc "),
        }
        for label, changed in changes.items():
            self.assertNotEqual(changed, line)
            bad = dict(row, mountinfo=row["mountinfo"].replace(line, changed))
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ValueError, "rooted proc view"),
            ):
                root.check_core(plan, bad, 1000, 250)
        second = row["mountinfo"].replace(
            b" /run/irlume/base.raw ro,nosuid,nodev,noexec - ext4 ",
            b" /run/irlume/base.raw ro,nosuid,nodev,noexec - proc ",
        )
        self.assertNotEqual(second, row["mountinfo"])
        with self.assertRaisesRegex(ValueError, "rooted proc view"):
            root.check_core(plan, dict(row, mountinfo=second), 1000, 250)
        # Only the observed kernel denials are allowed paths below /proc at all.
        for path in ("/proc/sys", "/proc/acpi", "/proc/1"):
            bad = dict(row, mountinfo=add_mount(row["mountinfo"], 60, path))
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ValueError, "missing or unexpected rooted"),
            ):
                root.check_core(plan, bad, 1000, 250)
        for path in root.KERNEL_DENIED:
            bad = copy.deepcopy(row)
            bad["denied"][path] = {"device": 3, "inode": 301, "mode": 0o100000}
            bad["mountinfo"] = add_cover(bad["mountinfo"], 60, path, "reg")
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ValueError, "rooted proc view"),
            ):
                root.check_core(plan, bad, 1000, 250)

    def test_core_match_returns_no_qualification_or_authority(self):
        plan, _ = selection()
        self.assertIsNone(root.check_core(plan, witness(plan), 1000, 250))

    def test_later_deadline_cannot_revive_expired_startup_observations(self):
        plan, _ = selection()
        with self.assertRaises(ValueError):
            root.check_core(plan, witness(plan), 7_000_000_100, 6_000_000_100)

    def test_namespaces_root_and_identity_maps_are_independently_checked(self):
        plan, _ = selection()
        row = witness(plan)
        # No namespace is the host's: PrivatePIDs= gives G its own PID
        # namespace and ProtectControlGroups=strict its own cgroup namespace.
        for key in root.NAMESPACES:
            self.assertNotEqual(row["namespaces"][key], plan["host_namespaces"][key])
            bad = copy.deepcopy(row)
            bad["namespaces"][key] = plan["host_namespaces"][key]
            with (
                self.subTest(namespace=key),
                self.assertRaisesRegex(ValueError, "rooted namespace mismatch: " + key),
            ):
                root.check_core(plan, bad, 1000, 250)
        for key, value in (
            ("root", {"device": 1, "inode": 99}),
            ("uid_map", b"0 0 4294967295\n"),
            ("gid_map", b"1000 1001 1\n"),
            ("uid_map", b"0 0 1\n1000 1000 1\n1000 1000 1\n"),
            ("fds", (0, 1, 2, 9)),
            ("fds", (0, 1, True)),
            ("fds", (0, 1)),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, **{key: value}), 1000, 250)

    def test_process_caps_privileges_ids_threads_and_duplicate_fields_refuse(self):
        plan, _ = selection()
        row = witness(plan)
        for before, after in (
            (b"Threads:\t1", b"Threads:\t2"),
            (b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"),
            (b"Uid:\t1000", b"Uid:\t0"),
            (b"Gid:\t1000", b"Gid:\t0"),
            *[
                (cap + b":\t0000000000000000", cap + b":\t0000000000000001")
                for cap in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb")
            ],
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                root.check_core(
                    plan,
                    dict(row, status=row["status"].replace(before, after)),
                    1000,
                    250,
                )
        with self.assertRaises(ValueError):
            root.check_core(
                plan, dict(row, status=row["status"] + b"Threads:\t1\n"), 1000, 250
            )

    def test_status_requires_seccomp_filter_mode(self):
        plan, _ = selection()
        row = witness(plan)
        self.assertIn(b"\nSeccomp:\t2\n", row["status"])
        self.assertIsNone(root.check_status(row["status"], 1000, 1000))
        for after in (b"Seccomp:\t0\n", b"Seccomp:\t1\n", b""):
            status = row["status"].replace(b"Seccomp:\t2\n", after)
            with self.subTest(after=after):
                with self.assertRaisesRegex(ValueError, "process status identity"):
                    root.check_status(status, 1000, 1000)
                with self.assertRaisesRegex(ValueError, "process status identity"):
                    root.check_core(plan, dict(row, status=status), 1000, 250)

    def test_status_requires_the_pid_namespace_init(self):
        plan, _ = selection()
        row = witness(plan)
        for before, after in (
            (b"Pid:\t1\n", b"Pid:\t4242\n"),
            (b"Pid:\t1\n", b""),
            (b"PPid:\t0\n", b"PPid:\t1\n"),
            (b"PPid:\t0\n", b""),
            # A host-visible proc lists every namespace level of the PID.
            (b"NSpid:\t1\n", b"NSpid:\t4242\t1\n"),
            (b"NSpid:\t1\n", b"NSpid:\t4242\n"),
            (b"NSpid:\t1\n", b""),
        ):
            status = row["status"].replace(before, after)
            self.assertNotEqual(status, row["status"])
            with self.subTest(before=before, after=after):
                with self.assertRaisesRegex(ValueError, "process status identity"):
                    root.check_status(status, 1000, 1000)
                with self.assertRaisesRegex(ValueError, "process status identity"):
                    root.check_core(plan, dict(row, status=status), 1000, 250)

    def test_denied_nodes_cannot_be_readable_or_host_backed(self):
        plan, _ = selection()
        row = witness(plan)
        for path in root.DENIED:
            for node in (
                {"device": 3, "inode": 300, "mode": 0o40755},
                {**plan["host_api"][path], "mode": 0o40000},
            ):
                bad = copy.deepcopy(row)
                bad["denied"][path] = node
                with self.subTest(path=path, node=node), self.assertRaises(ValueError):
                    root.check_core(plan, bad, 1000, 250)
        with self.assertRaises(ValueError):
            root.check_core(
                plan,
                dict(row, dev_log={"device": 3, "inode": 400, "mode": 0o140666}),
                1000,
                250,
            )

    def test_mounts_refuse_writable_sys_cgroup_shadow_journal_or_missing_bind(self):
        plan, _ = selection()
        row = witness(plan)
        for path in ("/", "/sys", "/sys/fs/cgroup", "/run/irlume/base.raw"):
            bad = row["mountinfo"].replace(
                f" {path} ro".encode(), f" {path} rw".encode()
            )
            with self.subTest(path=path), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, mountinfo=bad), 1000, 250)
        for path in (
            "/usr/lib",
            "/run/systemd/journal/socket",
            "/dev/shm/escape",
            "/sys/unknown",
            "/run/irlume/attempt/nested",
        ):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(
                    ValueError, "missing or unexpected rooted mount"
                ),
            ):
                root.check_core(
                    plan,
                    dict(row, mountinfo=add_mount(row["mountinfo"], 40, path)),
                    1000,
                    250,
                )
        bad = (
            b"\n".join(
                line
                for line in row["mountinfo"].splitlines()
                if b"base.raw" not in line
            )
            + b"\n"
        )
        with self.assertRaises(ValueError):
            root.check_core(plan, dict(row, mountinfo=bad), 1000, 250)

    def test_mounts_refuse_user_bus_and_runtime_dir(self):
        plan, _ = selection()
        row = witness(plan)
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        bus = f"/run/user/{plan['uid']}/bus"
        bad = dict(
            row,
            mountinfo=add_mount(
                row["mountinfo"], 40, bus, "ro,nosuid,nodev,noexec", "tmpfs"
            ),
        )
        with self.assertRaisesRegex(ValueError, "^missing or unexpected rooted mount$"):
            root.check_core(plan, bad, 1000, 250)
        user = f"/run/user/{plan['uid']}"
        for extra in (("/run/user",), ("/run/user", user), ("/run/user", user, bus)):
            entries = tuple(sorted((*row["run_entries"], *extra)))
            with (
                self.subTest(extra=extra),
                self.assertRaisesRegex(ValueError, "^unexpected rooted run entry$"),
            ):
                root.check_core(plan, dict(row, run_entries=entries), 1000, 250)

    def test_tmpfs_and_run_contents_are_bounded_and_private(self):
        plan, _ = selection()
        row = witness(plan)
        for path in ("/run", "/tmp"):
            for changes in (
                plan["host_api"][path],
                {"bytes": 17 * 1024**2},
                {"mode": 0o40777},
            ):
                bad = copy.deepcopy(row)
                bad["tmpfs"][path].update(changes)
                with (
                    self.subTest(path=path, changes=changes),
                    self.assertRaises(ValueError),
                ):
                    root.check_core(plan, bad, 1000, 250)
        with self.assertRaises(ValueError):
            root.check_core(
                plan,
                dict(row, run_entries=(*row["run_entries"], "/run/unknown")),
                1000,
                250,
            )

    def test_deadlines_and_bounded_proc_parsers_fail_closed(self):
        plan, _ = selection()
        row = witness(plan)
        for changes, deadline, now in (
            ({}, 250, 250),
            ({"finished_ns": 1001}, 1000, 1200),
            ({"started_ns": 201}, 1000, 250),
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, **changes), deadline, now)
        for key, bad in (
            ("uid_map", b"0 0 1\n" * 17),
            ("gid_map", b"9" * 4097),
            ("status", b"9" * 65537),
            ("mountinfo", b"9" * (1024**2 + 1)),
            ("mountinfo", row["mountinfo"] + b"broken"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                root.check_core(plan, dict(row, **{key: bad}), 1000, 250)

    def test_effective_mount_flags_types_and_propagation_are_not_just_names(self):
        plan, _ = selection()
        row = witness(plan)
        for before, after in (
            (b"/run rw,nosuid,nodev,noexec", b"/run rw,nosuid,nodev"),
            (b"/tmp rw,nosuid,nodev,noexec", b"/tmp rw,nosuid,noexec"),
            (b" - cgroup2 ", b" - tmpfs "),
            (b"/dev ro,nosuid,noexec", b"/dev rw,nosuid,noexec"),
            (b" - sysfs ", b" shared:42 - sysfs "),
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                root.check_core(
                    plan,
                    dict(row, mountinfo=row["mountinfo"].replace(before, after)),
                    1000,
                    250,
                )

    def test_optional_denial_and_kernel_mounts_have_explicit_negative_controls(self):
        plan, _ = selection()
        row, plain = witness(plan), witness(plan)["mountinfo"]
        for i, path in enumerate(root.DENIED):
            kind, mode = ("reg", 0o100000) if path == "/dev/ptmx" else ("dir", 0o40000)
            row["denied"][path] = {"device": 3, "inode": 300 + i, "mode": mode}
            row["mountinfo"] = add_cover(row["mountinfo"], 40 + i, path, kind)
            plain = add_mount(plain, 40 + i, path)
        self.assertIsNone(root.check_core(plan, row, 1000, 250))
        with self.assertRaisesRegex(ValueError, "not an inaccessible cover"):
            root.check_core(plan, dict(row, mountinfo=plain), 1000, 250)
        for path in root.DENIED:
            bad = copy.deepcopy(row)
            bad["denied"][path]["mode"] |= 0o755
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ValueError, "readable or unsupported"),
            ):
                root.check_core(plan, bad, 1000, 250)

    def test_real_private_pid_table_shows_the_host_cgroup_view(self):
        plan, _ = selection()
        self.assertEqual(R5_PRIVATE_PIDS.count(b"\n") - R5_NO_BUS.count(b"\n"), 1)
        view = root.parse_mountinfo(R5_NO_BUS)
        row = native_row(plan, R5_NO_BUS)
        # The real table carries the legacy leaf, rw device binds and no /root.
        self.assertIn("/sys/fs/cgroup/net_cls", view)
        self.assertTrue(all("rw" in view[p].options for p in root.DEVICE_BINDS))
        self.assertNotIn("/root", view)
        # ProtectControlGroups=yes showed the host tree and its legacy leaf.
        with self.assertRaisesRegex(ValueError, "^missing or unexpected rooted mount$"):
            root.check_core(plan, row, 1000, 250)
        leaf = b" /sys/fs/cgroup/net_cls "
        leafless = b"".join(
            line for line in R5_NO_BUS.splitlines(keepends=True) if leaf not in line
        )
        self.assertEqual(R5_NO_BUS.count(b"\n") - leafless.count(b"\n"), 1)
        self.assertIsNone(root.check_core(plan, native_row(plan, leafless), 1000, 250))
        for data, message in (
            (R5_HOST_PROC, "stacked mount: /proc/sys/fs/binfmt_misc"),
            (R5_PID_ONLY, "stacked mount: /proc/sys/fs/binfmt_misc"),
            # The recorded table with the user-bus bind is no longer the profile.
            (R5_PRIVATE_PIDS, "^missing or unexpected rooted mount$"),
        ):
            with self.assertRaisesRegex(ValueError, message):
                root.check_core(plan, dict(row, mountinfo=data), 1000, 250)

    def test_native_tables_of_the_bus_free_profile_are_accepted(self):
        plan, _ = selection()
        # R5_ARCHHOST was recorded under ProtectControlGroups=yes. Its single
        # cgroup2 on /sys, root /, has the shape strict leaves there
        # (R5_ARCHHOST_STRICT), so the namespace rule and G's cgroup ID binding
        # tell the two apart, not the mount table.
        for label, data in (
            ("strict", R5_STRICT),
            ("archhost strict", R5_ARCHHOST_STRICT),
            ("archhost", R5_ARCHHOST),
        ):
            with self.subTest(label=label):
                row = native_row(plan, data)
                self.assertIsNone(root.check_core(plan, row, 1000, 250))
        # The laptop's yes table shows the host's legacy hierarchy.
        with self.assertRaisesRegex(ValueError, "^missing or unexpected rooted mount$"):
            root.check_core(plan, native_row(plan, R5_TRACING), 1000, 250)

    def test_occluded_debugfs_is_one_exact_shape(self):
        # On the strict laptop table, beside its occluded cgroup.
        plan, _ = selection()

        def line(number, parent, path, kind, device, mount_root=b"/", flags=b"rw"):
            return b"%d %d %s %s %s %s,nosuid,nodev,noexec,relatime - %s\n" % (
                number,
                parent,
                device,
                mount_root,
                path,
                flags,
                kind,
            )

        debug, tracing = b"/sys/kernel/debug", b"/sys/kernel/debug/tracing"
        debugfs = line(1901, 1892, debug, b"debugfs debugfs rw,seclabel", b"0:9")
        tracefs = line(1902, 1901, tracing, b"tracefs tracefs rw,seclabel", b"0:14")
        tmpfs = (
            b"tmpfs tmpfs rw,seclabel,size=3231088k,nr_inodes=807772,mode=700,"
            b"uid=1000,gid=1000,inode64"
        )
        dir_root = b"/systemd/inaccessible/dir"
        cover = line(1906, 1901, debug, tmpfs, b"0:84", dir_root, b"ro")
        for row in (debugfs, tracefs, cover):
            self.assertEqual(R5_STRICT.count(row), 1)

        def edit(row, old, new, data=R5_STRICT):
            self.assertEqual(row.count(old), 1)
            return data.replace(row, row.replace(old, new))

        def extra(row, data=R5_STRICT):
            return data + row

        def hide(path, kind, device):
            """Stack the path's cover on the host filesystem it replaces."""
            old = b" 1892 0:84 %s %s " % (dir_root, path)
            self.assertEqual(R5_STRICT.count(old), 1)
            data = R5_STRICT.replace(old, b" 1908 0:84 %s %s " % (dir_root, path))
            return extra(line(1908, 1892, path, kind, device), data)

        for label, data in (
            ("tracefs automount", R5_STRICT),
            ("no tracefs", R5_STRICT.replace(tracefs, b"")),
        ):
            with self.subTest(label=label):
                row = native_row(plan, data)
                self.assertIsNone(root.check_core(plan, row, 1000, 250))
        occluded = "^occluded debugfs$"
        refused = (
            (
                "second debugfs",
                extra(
                    line(1908, 1901, debug, b"debugfs debugfs rw", b"0:9"),
                    edit(cover, b"1906 1901", b"1906 1908"),
                ),
            ),
            (
                "debugfs on the cover",
                extra(debugfs.replace(b"1901 1892", b"1908 1906")),
            ),
            ("cover on the cover", extra(cover.replace(b"1906 1901", b"1908 1906"))),
            ("tmpfs on the cover", extra(line(1908, 1906, debug, tmpfs, b"0:99"))),
            (
                "mount below the cover",
                extra(line(1908, 1906, debug + b"/x", tmpfs, b"0:84", dir_root, b"ro")),
            ),
            (
                "debugfs at tracing",
                edit(tracefs, b"tracefs tracefs", b"debugfs debugfs"),
            ),
            ("tracefs elsewhere", edit(tracefs, b"/tracing ", b"/trace ")),
            ("tracefs on the cover", edit(tracefs, b"1902 1901", b"1902 1906")),
            ("tracefs on /sys", edit(tracefs, b"1902 1901", b"1902 1892")),
            ("tracefs source", edit(tracefs, b"tracefs tracefs", b"tracefs none")),
            ("tracefs root", edit(tracefs, b" / /sys", b" /instances /sys")),
            ("other filesystem", edit(tracefs, b"tracefs tracefs", b"tmpfs tmpfs")),
            ("tracefs type", edit(tracefs, b"- tracefs tracefs", b"- tmpfs tracefs")),
            ("two tracefs", extra(tracefs.replace(b"1902 1901", b"1908 1902"))),
            (
                "tracefs child",
                extra(
                    line(1908, 1902, tracing + b"/x", b"tracefs tracefs rw", b"0:14")
                ),
            ),
            (
                "foreign child of the debugfs",
                extra(line(1908, 1901, b"/tmp/x", b"tmpfs tmpfs rw", b"0:99")),
            ),
            ("cover beside the debugfs", edit(cover, b"1906 1901", b"1906 1892")),
            ("tracefs pair", extra(tracefs.replace(b"1902 1901", b"1908 1901"))),
            ("debugfs off /sys", edit(debugfs, b"1901 1892", b"1901 1786")),
            ("debugfs type", edit(debugfs, b"- debugfs debugfs", b"- tmpfs debugfs")),
            ("debugfs source", edit(debugfs, b"debugfs debugfs", b"debugfs none")),
            ("debugfs root", edit(debugfs, b" / /sys", b" /x /sys")),
            ("shared debugfs", edit(debugfs, b"relatime -", b"relatime shared:7 -")),
            ("slave tracefs", edit(tracefs, b"relatime -", b"relatime master:7 -")),
            ("shared cover", edit(cover, b"relatime -", b"relatime shared:9 -")),
            ("reg cover", edit(cover, b"inaccessible/dir", b"inaccessible/reg")),
            ("other cover root", edit(cover, dir_root, b"/x")),
            ("writable cover", edit(cover, b" ro,nosuid", b" rw,nosuid")),
            ("executable cover", edit(cover, b"nodev,noexec,", b"nodev,")),
            ("debugfs cover", edit(cover, b"tmpfs tmpfs", b"debugfs debugfs")),
            (
                "hidden security view",
                hide(b"/sys/kernel/security", b"securityfs securityfs rw", b"0:8"),
                "^stacked mount: /sys/kernel/security$",
            ),
            (
                "hidden tracing view",
                hide(b"/sys/kernel/tracing", b"tracefs tracefs rw,seclabel", b"0:14"),
                "^stacked mount: /sys/kernel/tracing$",
            ),
        )
        # The parser takes these; the witness check refuses them.
        witnessed = (
            (
                "cover device",
                edit(cover, b"1901 0:84", b"1901 0:99"),
                "^inaccessible covers disagree$",
            ),
            (
                "cover prefix",
                edit(cover, b" /systemd/", b" /x/systemd/"),
                "^inaccessible covers disagree$",
            ),
            (
                "no cover",
                R5_STRICT.replace(cover, b""),
                "^missing or unexpected rooted mount$",
            ),
            (
                "neither cover nor tracefs",
                R5_STRICT.replace(cover, b"").replace(tracefs, b""),
                "^writable protected rooted mount$",
            ),
        )
        good = native_row(plan, R5_STRICT)
        for label, data, *message in refused + witnessed:
            message = message[0] if message else occluded
            self.assertNotEqual(data, R5_STRICT)
            with self.subTest(label=label):
                if label not in {case[0] for case in witnessed}:
                    with self.assertRaisesRegex(ValueError, message):
                        root.parse_mountinfo(data)
                with self.assertRaisesRegex(ValueError, message):
                    root.check_core(plan, dict(good, mountinfo=data), 1000, 250)

    def test_kernel_views_are_single_covers_or_absent(self):
        plan, _ = selection()
        base = witness(plan)
        for path in root.KERNEL_HIDDEN:
            row = copy.deepcopy(base)
            lines = row["mountinfo"].splitlines(keepends=True)
            other = [x for x in lines if f" {path} ".encode() not in x]
            absent = dict(row, mountinfo=b"".join(other))
            absent["denied"] = dict(row["denied"], **{path: None})
            self.assertIsNone(root.check_core(plan, absent, 1000, 250))
            node = {"device": 3, "inode": 650, "mode": 0o40000}
            covered = dict(absent, denied=dict(absent["denied"], **{path: node}))
            covered["mountinfo"] = add_cover(absent["mountinfo"], 70, path)
            self.assertIsNone(root.check_core(plan, covered, 1000, 250))
            plain = add_mount(absent["mountinfo"], 70, path, "ro,nosuid,nodev,noexec")
            sealed = "ro,nosuid,nodev,noexec"
            cases = (
                ("node without cover", dict(covered, mountinfo=absent["mountinfo"])),
                ("cover without node", dict(covered, denied=absent["denied"])),
                (
                    "original top",
                    dict(
                        covered,
                        mountinfo=add_mount(
                            absent["mountinfo"], 70, path, sealed, "debugfs"
                        ),
                    ),
                ),
                ("other root", dict(covered, mountinfo=plain)),
                (
                    "reg cover",
                    dict(
                        covered,
                        mountinfo=add_cover(absent["mountinfo"], 70, path, "reg"),
                    ),
                ),
                (
                    "writable",
                    dict(
                        covered,
                        mountinfo=covered["mountinfo"].replace(
                            f" {path} ro,".encode(), f" {path} rw,".encode()
                        ),
                    ),
                ),
                (
                    "executable",
                    dict(
                        covered,
                        mountinfo=covered["mountinfo"].replace(
                            f" {path} ro,nosuid,nodev,noexec,".encode(),
                            f" {path} ro,nosuid,nodev,".encode(),
                        ),
                    ),
                ),
                (
                    "other device",
                    dict(
                        covered,
                        mountinfo=add_mount(
                            absent["mountinfo"],
                            70,
                            path,
                            sealed,
                            source_root="/systemd/inaccessible/dir",
                            device="0:99",
                        ),
                    ),
                ),
                (
                    "other prefix",
                    dict(
                        covered,
                        mountinfo=add_mount(
                            absent["mountinfo"],
                            70,
                            path,
                            sealed,
                            source_root="/x/systemd/inaccessible/dir",
                            device=COVER_DEVICE,
                        ),
                    ),
                ),
                (
                    "propagation",
                    dict(
                        covered,
                        mountinfo=covered["mountinfo"].replace(
                            f" {path} ro,nosuid,nodev,noexec,relatime -".encode(),
                            f" {path} ro,nosuid,nodev,noexec,relatime master:3 -".encode(),
                        ),
                    ),
                ),
                (
                    "stacked on its top",
                    dict(
                        covered,
                        mountinfo=add_cover(
                            add_mount(absent["mountinfo"], 69, path, sealed, "debugfs"),
                            70,
                            path,
                        ),
                    ),
                ),
            )
            messages = {
                "node without cover": "kernel cover and node disagree",
                "cover without node": "denial target reported absent",
                "writable": "writable protected rooted mount",
                "other device": "inaccessible covers disagree",
                "other prefix": "inaccessible covers disagree",
                "propagation": "rooted mount is not private",
                # A debugfs under a cover is refused as a shape, not a stack.
                "stacked on its top": (
                    "^occluded debugfs$"
                    if path == "/sys/kernel/debug"
                    else "stacked mount: " + path
                ),
            }
            for label, bad in cases:
                self.assertNotEqual(bad["mountinfo"], b"")
                with (
                    self.subTest(path=path, label=label),
                    self.assertRaisesRegex(
                        ValueError,
                        messages.get(label, "denial is not an inaccessible cover"),
                    ),
                ):
                    root.check_core(plan, bad, 1000, 250)

    def test_visible_legacy_cgroup_leaf_is_refused(self):
        plan, _ = selection()
        row = witness(plan)

        def leaf(name, options="ro,relatime", filesystem="cgroup", **kwargs):
            kwargs.setdefault("super_options", "rw," + name)
            return add_mount(
                row["mountinfo"],
                80,
                "/sys/fs/cgroup/" + name,
                options,
                filesystem,
                **kwargs,
            )

        # Under strict a legacy hierarchy only stays hidden below the fresh
        # cgroup2 (occluded_cgroup); on G's own cgroup2 it is unexpected.
        for name in (
            "net_cls",
            "net_cls,net_prio",
            "net_prio",
            "memory",
            "name=systemd",
        ):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    ValueError, "^missing or unexpected rooted mount$"
                ),
            ):
                root.check_core(plan, dict(row, mountinfo=leaf(name)), 1000, 250)

    def test_occluded_cgroup_is_one_exact_shape(self):
        plan, _ = selection()
        good = native_row(plan, R5_STRICT)
        self.assertIsNone(root.check_core(plan, good, 1000, 250))
        host = (
            b"1895 1892 0:30 /../../../../.. /sys/fs/cgroup "
            b"rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 "
            b"rw,seclabel,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting\n"
        )
        legacy = (
            b"1896 1895 0:85 / /sys/fs/cgroup/net_cls rw,relatime"
            b" - cgroup net_cls rw,seclabel,net_cls\n"
        )
        cover = (
            b"1905 1895 0:30 / /sys/fs/cgroup "
            b"ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 "
            b"rw,seclabel,nsdelegate,memory_recursiveprot,memory_hugetlb_accounting\n"
        )
        for row in (host, legacy, cover):
            self.assertEqual(R5_STRICT.count(row), 1)

        def edit(row, old, new, data=R5_STRICT):
            self.assertEqual(row.count(old), 1)
            return data.replace(row, row.replace(old, new))

        def extra(row, data=R5_STRICT):
            return data + row

        hidden = R5_STRICT.replace(host, b"").replace(legacy, b"")
        direct = edit(cover, b"1905 1895", b"1905 1892", hidden)
        single = cover.replace(b"1905 1895", b"1905 1892")
        view = root.parse_mountinfo(R5_STRICT)
        self.assertEqual(len(view), R5_STRICT.count(b"\n") - 4)
        self.assertEqual(
            (view["/sys/fs/cgroup"].number, view["/sys/fs/cgroup"].parent),
            (1905, 1895),
        )
        self.assertNotIn("/sys/fs/cgroup/net_cls", view)
        for label, data in (
            ("host copy and legacy hidden", R5_STRICT),
            ("host copy hidden", R5_STRICT.replace(legacy, b"")),
            # Without a locked child systemd can unmount the host copy.
            ("cover on /sys", direct),
            (
                "other legacy name",
                R5_STRICT.replace(
                    legacy, legacy.replace(b"net_cls", b"net_cls,net_prio")
                ),
            ),
            ("one level up", edit(host, b"/../../../../..", b"/..")),
        ):
            with self.subTest(label=label):
                self.assertIsNone(
                    root.check_core(plan, dict(good, mountinfo=data), 1000, 250)
                )
        occluded = "^occluded cgroup$"
        refused = (
            ("host root /", edit(host, b"/../../../../..", b"/")),
            ("host root below the namespace", edit(host, b"/../../../../..", b"/x")),
            ("host off /sys", edit(host, b"1895 1892", b"1895 1786")),
            ("host on /sys/fs", edit(host, b"1895 1892", b"1895 1894")),
            ("host source", edit(host, b"cgroup2 cgroup2", b"cgroup2 none")),
            ("host shared", edit(host, b"relatime -", b"relatime shared:7 -")),
            ("cover device", edit(cover, b"1895 0:30", b"1895 0:31")),
            ("cover root", edit(cover, b" / /sys", b" /x /sys")),
            ("cover type", edit(cover, b"- cgroup2 cgroup2", b"- tmpfs cgroup2")),
            ("writable cover", edit(cover, b" ro,nosuid", b" rw,nosuid")),
            ("shared cover", edit(cover, b"relatime -", b"relatime shared:9 -")),
            ("slave cover", edit(cover, b"relatime -", b"relatime master:9 -")),
            ("cover beside the host", edit(cover, b"1905 1895", b"1905 1892")),
            ("cover on the legacy", edit(cover, b"1905 1895", b"1905 1896")),
            (
                "second legacy",
                extra(
                    b"1908 1895 0:86 / /sys/fs/cgroup/net_prio rw,relatime"
                    b" - cgroup net_prio rw,net_prio\n"
                ),
            ),
            ("legacy name", edit(legacy, b"/net_cls ", b"/memory ")),
            # A v1 hierarchy named for its own controllers, but not a VPN's.
            (
                "legacy memory hierarchy",
                R5_STRICT.replace(legacy, legacy.replace(b"net_cls", b"memory")),
            ),
            (
                "legacy path",
                edit(legacy, b"/sys/fs/cgroup/net_cls", b"/sys/fs/cgroup/x"),
            ),
            ("legacy deeper", edit(legacy, b"/net_cls ", b"/net_cls/x ")),
            ("legacy type", edit(legacy, b"- cgroup net_cls", b"- cgroup2 net_cls")),
            ("legacy root", edit(legacy, b" / /sys", b" /x /sys")),
            ("legacy controller", edit(legacy, b"seclabel,net_cls", b"seclabel")),
            (
                "legacy controllers partial",
                edit(legacy, b"/net_cls ", b"/net_cls,net_prio "),
            ),
            ("legacy on the cover", edit(legacy, b"1896 1895", b"1896 1905")),
            ("legacy slave", edit(legacy, b"relatime -", b"relatime master:4 -")),
            (
                "foreign child of the host copy",
                extra(b"1908 1895 0:99 / /tmp/x rw - tmpfs tmpfs rw\n"),
            ),
            (
                "child of the hidden legacy",
                extra(
                    b"1908 1896 0:99 / /sys/fs/cgroup/net_cls/x rw - tmpfs tmpfs rw\n"
                ),
            ),
            (
                "third cgroup2",
                extra(cover.replace(b"1905 1895", b"1908 1905")),
            ),
            (
                "visible legacy on the cover",
                extra(legacy.replace(b"1896 1895", b"1908 1905")),
            ),
            (
                "visible host copy",
                hidden.replace(cover, b"") + host,
                "^upward mount root$",
            ),
        )
        # The parser takes these; the witness check refuses them.
        witnessed = (
            (
                "visible legacy on a single cgroup2",
                extra(legacy.replace(b"1896 1895", b"1896 1905"), direct),
                "^missing or unexpected rooted mount$",
            ),
            (
                "cover root below the namespace",
                edit(single, b" / /sys", b" /x /sys", direct),
                "^rooted cgroup view$",
            ),
            (
                "writable single cgroup2",
                edit(single, b" ro,nosuid", b" rw,nosuid", direct),
                "^writable protected rooted mount$",
            ),
        )
        for label, data, *message in refused + witnessed:
            message = message[0] if message else occluded
            self.assertNotEqual(data, R5_STRICT)
            with self.subTest(label=label):
                if label not in {case[0] for case in witnessed}:
                    with self.assertRaisesRegex(ValueError, message):
                        root.parse_mountinfo(data)
                with self.assertRaisesRegex(ValueError, message):
                    root.check_core(plan, dict(good, mountinfo=data), 1000, 250)

    def test_device_binds_are_nosuid_devtmpfs_leaves_on_one_device(self):
        plan, _ = selection()
        row = witness(plan)
        lines = row["mountinfo"].splitlines(keepends=True)
        null = next(x for x in lines if b" /dev/null " in x)
        self.assertIn(b" /null /dev/null rw,nosuid - devtmpfs ", null)
        cases = (
            ("root", null.replace(b" /null /dev/null ", b" /zero /dev/null ")),
            ("type", null.replace(b" - devtmpfs ", b" - tmpfs ")),
            ("suid", null.replace(b" rw,nosuid ", b" rw ")),
            ("device", null.replace(b" 0:7 ", b" 0:8 ")),
            ("propagation", null.replace(b" rw,nosuid ", b" rw,nosuid shared:5 ")),
        )
        messages = {
            "device": "device binds disagree",
            "propagation": "rooted mount is not private",
        }
        for label, changed in cases:
            self.assertNotEqual(changed, null)
            bad = dict(row, mountinfo=row["mountinfo"].replace(null, changed))
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    ValueError, messages.get(label, "unexpected device bind")
                ),
            ):
                root.check_core(plan, bad, 1000, 250)
        # Absent binds stay optional; a read-only one is also accepted.
        without = b"".join(x for x in lines if x != null)
        readonly = row["mountinfo"].replace(null, null.replace(b" rw,", b" ro,"))
        for data in (without, readonly):
            self.assertIsNone(
                root.check_core(plan, dict(row, mountinfo=data), 1000, 250)
            )

    def test_root_home_window_is_refused(self):
        plan, _ = selection()
        row = witness(plan)
        for options in ("rw,relatime", "ro,relatime"):
            data = add_mount(
                row["mountinfo"],
                90,
                "/root",
                options,
                "btrfs",
                source_root="/private/runtime/root",
            )
            with (
                self.subTest(options=options),
                self.assertRaisesRegex(ValueError, "missing or unexpected rooted"),
            ):
                root.check_core(plan, dict(row, mountinfo=data), 1000, 250)


if __name__ == "__main__":
    unittest.main()

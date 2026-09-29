#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Exercise the packaged password verifier only in the marked NixOS test VM."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import stat
import subprocess

USER = "irlume-recovery-test"
HELPER = Path("/run/irlume-recovery/irlume-password-verify")
SERVICE = Path("/etc/pam.d/irlume-retry-reset")


def run(argv, *, data=None, account=None):
    return subprocess.run(
        argv, input=data, capture_output=True, text=True, timeout=60,
        user=account.pw_uid if account else None,
        group=account.pw_gid if account else None,
        extra_groups=os.getgrouplist(account.pw_name, account.pw_gid) if account else None,
    )


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def status(account, strikes, budget, failures, available=True):
    result = run(["irlume", "retry", "status", "--user", USER], account=account)
    availability = "available for supported local accounts" if available else "unavailable on this installation"
    pattern = (
        rf"Face retry state for '{re.escape(USER)}': {strikes} recorded failures, 0s cooldown\.\n"
        rf"Cumulative face requests: {budget}/50 consecutive unsuccessful; available after any cooldown\.\n"
        rf"Password-verified retry reset: {availability}; {failures} failed checks, 0s cooldown\.\n"
        r"Ordinary password login remains available\.\n?"
    )
    require(result.returncode == 0 and re.fullmatch(pattern, result.stdout) is not None,
            "retry availability or exact counter values differ")


def protected(path, mode):
    meta = path.lstat()
    require(stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode) == mode,
            "trusted recovery input is not a regular file with the expected mode")
    for item in (path, *path.parents):
        info = item.stat()
        require(info.st_uid == 0 and info.st_mode & 0o022 == 0, "untrusted recovery ancestry")


def main():
    require(os.geteuid() == 0, "guest root required")
    require(run(["systemd-detect-virt"]).stdout.strip() in ("qemu", "kvm"), "QEMU required")
    require(Path("/etc/irlume-recovery-test-marker").read_text() == "disposable-nixos-recovery-test",
            "test marker required")
    require(not list(Path("/dev").glob("video*")), "camera devices must be absent")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    account = pwd.getpwnam(USER)
    password = secrets.token_urlsafe(36)
    require(run(["chpasswd"], data=f"{USER}:{password}\n").returncode == 0, "password setup failed")
    retry = Path("/var/lib/irlume/retry")
    retry.mkdir(mode=0o700, exist_ok=True)
    for name, value in {
        f"{account.pw_uid}.json": {"version": 2, "uid": account.pw_uid, "account": USER,
                                  "strikes": 2, "cooldown": None,
                                  "budget": {"unsuccessful_requests": 7, "pending": False}},
        f"{account.pw_uid}.reset.json": {"version": 1, "uid": account.pw_uid, "account": USER,
                                        "failures": 0, "pending": False, "cooldown": None},
    }.items():
        with (retry / name).open("x") as stream:
            json.dump(value, stream)

    # This must succeed with the standard group-writable Nix store present.
    require(Path("/nix/store").stat().st_mode & 0o020 != 0, "Nix store fixture does not reproduce the boundary")
    status(account, 2, 7, 0)
    protected(HELPER, 0o755)
    protected(SERVICE, 0o644)
    require(stat.S_IMODE(HELPER.parent.stat().st_mode) == 0o700, "runtime directory is not private")
    package = Path(Path("/etc/irlume-recovery-test-package").read_text())
    require(hashlib.sha256(HELPER.read_bytes()).digest()
            == hashlib.sha256((package / "libexec/irlume-password-verify").read_bytes()).digest(),
            "runtime helper differs from selected package")
    require(run(["systemctl", "stop", "irlumed.service"]).returncode == 0, "daemon stop failed")
    require(not HELPER.parent.exists(), "stopped service retained the runtime helper")
    require(run(["systemctl", "start", "irlumed.service"]).returncode == 0, "daemon restart failed")
    protected(HELPER, 0o755)
    require(hashlib.sha256(HELPER.read_bytes()).digest()
            == hashlib.sha256((package / "libexec/irlume-password-verify").read_bytes()).digest(),
            "restart did not restore the selected helper")
    for path, mode in ((HELPER, 0o755), (SERVICE, 0o644)):
        require(run(["test", "-w", str(path)], account=account).returncode == 1,
                "ordinary account can modify a trusted recovery input")
        path.chmod(mode | 0o022)
        try:
            status(account, 2, 7, 0, available=False)
            require(run(["irlume", "retry", "reset", "--user", USER],
                        data=password + "\n", account=account).returncode == 1,
                    "unsafe recovery input allowed a reset")
            status(account, 2, 7, 0, available=False)
        finally:
            path.chmod(mode)
        status(account, 2, 7, 0)

    reset = ["irlume", "retry", "reset", "--user", USER]
    require(run(reset, data="wrong-" + password + "\n", account=account).returncode == 1,
            "wrong password was not normally refused")
    status(account, 2, 7, 1)
    require(run(reset, data=password + "\n", account=account).returncode == 0,
            "correct password reset failed")
    status(account, 0, 0, 0)
    print("PASS: trusted Nix recovery inputs, unsafe-mode refusal, wrong/correct password reset")


if __name__ == "__main__":
    main()

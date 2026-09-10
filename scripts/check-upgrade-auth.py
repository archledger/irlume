#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded authentication checks for the marked disposable upgrade guests only.

Never invoke this on an installed host. The guard runs before any mutation.
No enrollment, biometric template, recovery envelope or physical device is used.

Source contract at candidate bf323a7e:
* crates/irlume-daemon/src/retry_throttle.rs: Record v2, FaceBudget, Store::path.
* crates/irlume-daemon/src/retry_throttle/recovery.rs: Attempts v1, status/reset.
* crates/irlume-cli/src/retry.rs and main.rs::read_password: CLI and stdin.
* crates/irlume-daemon/src/retry_recovery.rs: packaged password-helper gate.
The v0.11.3 tree has no retry_throttle/retry_recovery or retry CLI. Synthetic
counter preservation does not establish enforcement by that old release, nor
biometric enrollment usability. Counter fixtures deliberately avoid cooldowns
and pending operations, which status can legitimately settle or rewrite.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import shutil
import stat
import subprocess
import sys

STAGES = ("old-install", "candidate-upgrade", "old-rollback", "candidate-reupgrade")
MARKER = Path("/run/irlume-upgrade-disposable")
MARKER_BYTES = b"irlume-upgrade-20260910"
PRIVATE = Path("/var/tmp/irlume-upgrade-private")
USER = "irlume-upgrade-fixture"
ADMIN = "qualifier"
SERVICE = "irlume-upgrade-fallback"
PAM = Path("/etc/pam.d") / SERVICE
RETRY = Path("/var/lib/irlume/retry")
ENV = {"PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/"}


class Failure(Exception):
    """Only fixed, non-sensitive assertion identifiers may be reported."""


def require(condition, code):
    if not condition:
        raise Failure(code)


def command(argv, *, input_text=None, capture=True, account=None):
    options = {}
    if account is not None:
        options = {"user": account.pw_uid, "group": account.pw_gid,
                   "extra_groups": os.getgrouplist(account.pw_name, account.pw_gid)}
    try:
        result = subprocess.run(
            argv, input=input_text, text=True, env=ENV, cwd="/", timeout=45,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, **options,
        )
    except subprocess.TimeoutExpired:
        raise Failure("command-timeout") from None
    except OSError:
        raise Failure("command-unavailable") from None
    return result.returncode, result.stdout if capture else ""


def admit_guest():
    require(os.geteuid() == 0, "root-required")
    code, kind = command(["systemd-detect-virt", "--vm"])
    kind = kind.strip()
    require(code == 0 and kind in ("qemu", "kvm"), "qemu-kvm-required")
    try:
        fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            meta = os.fstat(stream.fileno())
            require(stat.S_ISREG(meta.st_mode), "marker-not-regular")
            require(meta.st_uid == 0 and meta.st_mode & 0o022 == 0, "marker-owner-or-mode")
            marker = stream.read(len(MARKER_BYTES) + 1)
    except OSError:
        raise Failure("marker-unreadable-or-symlink") from None
    require(marker == MARKER_BYTES, "marker-mismatch")
    return kind


def trusted_directory(path, mode=None):
    # Check every ancestor; /var/tmp is the sole intentionally world-writable
    # ancestor. The private child is created exclusively and must remain 0700.
    for item in (path, *path.parents):
        meta = item.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0,
                "directory-owner-or-type")
        if item == Path("/var/tmp"):
            require(bool(meta.st_mode & stat.S_ISVTX), "private-parent-not-sticky")
        else:
            require(meta.st_mode & 0o022 == 0, "directory-writable")
    if mode is not None:
        require(path.stat().st_mode & 0o7777 == mode, "directory-mode")


def create_private(path, payload):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0
                and meta.st_mode & 0o7777 == 0o600 and meta.st_nlink == 1
                and meta.st_size <= 65536, "private-file-metadata")
        return stream.read(65537)


def save_manifest(manifest):
    target = PRIVATE / "manifest.json"
    temp = PRIVATE / ("manifest-" + secrets.token_hex(8))
    create_private(temp, json.dumps(manifest, sort_keys=True).encode())
    os.replace(temp, target)


def check_stage(stage, previous):
    index = STAGES.index(stage)
    expected = STAGES[index - 1] if index else None
    require(previous == expected, "stage-order")


def admin_identity():
    account = pwd.getpwnam(ADMIN)
    require(account.pw_uid != 0 and account.pw_name != USER, "independent-admin-required")
    require(command(["sudo", "-n", "true"], capture=False, account=account)[0] == 0,
            "independent-admin-sudo-failed")
    require(any(command(["systemctl", "is-active", "--quiet", service], capture=False)[0] == 0
                for service in ("ssh.service", "sshd.service")), "admin-ssh-service-inactive")
    # The parent's live SSH session remains the access qualification. Check the
    # account and authorized keys remain the same without emitting their content.
    keys = Path(account.pw_dir) / ".ssh/authorized_keys"
    require(keys.is_file() and keys.stat().st_size > 0, "admin-ssh-key-missing")
    return {"uid": account.pw_uid, "gid": account.pw_gid,
            "home": account.pw_dir, "shell": account.pw_shell,
            "groups": sorted(os.getgrouplist(ADMIN, account.pw_gid)),
            "keys_sha256": hashlib.sha256(keys.read_bytes()).hexdigest()}


def packaged_module():
    if shutil.which("dpkg-query", path=ENV["PATH"]):
        code, files = command(["dpkg-query", "-L", "irlume"])
    elif shutil.which("pacman", path=ENV["PATH"]):
        code, files = command(["pacman", "-Qlq", "irlume"])
    elif shutil.which("rpm", path=ENV["PATH"]):
        code, files = command(["rpm", "-ql", "irlume"])
    else:
        raise Failure("unsupported-package-manager")
    require(code == 0, "installed-package-query-failed")
    paths = [Path(line) for line in files.splitlines()
             if line.startswith("/") and line.endswith("/security/pam_irlume.so")]
    require(len(paths) == 1, "packaged-pam-module-ambiguous")
    module = paths[0]
    require(module.is_file() and module.stat().st_size > 0, "packaged-pam-module-missing")
    require(module.stat().st_uid == 0 and module.stat().st_mode & 0o022 == 0,
            "packaged-pam-module-permissions")
    return module


def pam_contents(module):
    return (f"auth sufficient {module}\nauth required pam_unix.so\n"
            "account required pam_unix.so\n").encode()


def pam_checks(password):
    results = []
    # pamtester 0.1.2 app.c:273-275,462 maps PAM rejection to exit 1;
    # pamtester.c:238-243 returns it unchanged. Signals/other exits are not
    # evidence of password rejection, even after the positive control passed.
    for supplied, expected in ((password, 0), ("wrong-" + password, 1)):
        code, _ = command(["pamtester", SERVICE, USER, "authenticate", "acct_mgmt"],
                          input_text=supplied + "\n", capture=False)
        require(code == expected,
                "pam-correct-password-refused" if expected == 0
                else "pam-wrong-password-rejection-unconfirmed")
        results.append(code)
    return {"correct_password_exit": results[0], "wrong_password_exit": results[1]}


def retry_records(uid):
    return {
        f"{uid}.json": {"version": 2, "uid": uid, "account": USER, "strikes": 2,
                        "cooldown": None,
                        "budget": {"unsuccessful_requests": 7, "pending": False}},
        f"{uid}.reset.json": {"version": 1, "uid": uid, "account": USER,
                              "failures": 0, "pending": False, "cooldown": None},
    }


def retry_fingerprints(uid):
    result = {}
    for name in retry_records(uid):
        payload = read_private(RETRY / name)
        result[name] = hashlib.sha256(payload).hexdigest()
    return result


def seed_retry(uid):
    trusted_directory(RETRY.parent)
    if not RETRY.exists():
        RETRY.mkdir(mode=0o700)
    trusted_directory(RETRY, 0o700)
    # Same directory flock as the daemon's Store::lock. Only nonexistent files
    # for this newly created account are written, never a pre-existing record.
    fd = os.open(RETRY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        records = retry_records(uid)
        require(all(not (RETRY / name).exists() and not (RETRY / name).is_symlink()
                    for name in records), "retry-record-already-exists")
        for name, record in records.items():
            create_private(RETRY / name, json.dumps(record, separators=(",", ":")).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return retry_fingerprints(uid)


def check_status(output, strikes, budget, recovery):
    # Full lines distinguish prospective/unknown history from measured counts.
    pattern = (
        rf"Face retry state for '{re.escape(USER)}': {strikes} recorded failures, 0s cooldown\.\n"
        rf"Cumulative face requests: {budget}/50 consecutive unsuccessful; available after any cooldown\.\n"
        rf"Password-verified retry reset: (available for supported local accounts|unavailable on this installation); "
        rf"{recovery} failed checks, 0s cooldown\.\nOrdinary password login remains available\.\n?"
    )
    match = re.fullmatch(pattern, output)
    require(match is not None, "retry-status-mismatch")
    return match.group(1) == "available for supported local accounts"


def status(account, strikes=2, budget=7, recovery=1):
    code, output = command(["irlume", "retry", "status", "--user", USER], account=account)
    require(code == 0, "retry-status-command-failed")
    return check_status(output, strikes, budget, recovery)


def run_stage(stage, report):
    # All subprocesses inherit this no-core policy after admission, so accidental
    # child failure cannot leave a password-bearing core in exported evidence.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require(not list(Path("/dev").glob("video*")), "camera-device-present")
    trusted_directory(Path("/usr/local/bin"))
    for name in ("pamtester", "useradd", "chpasswd", "irlume", "sudo", "systemctl"):
        require(shutil.which(name, path=ENV["PATH"]) is not None, "guest-dependency-missing")
    admin = admin_identity()
    module = packaged_module()
    trusted_directory(PAM.parent)
    expected_pam = pam_contents(module)
    if stage == "old-install":
        require(not PRIVATE.exists() and not PRIVATE.is_symlink(), "fixture-already-exists")
        require(not PAM.exists() and not PAM.is_symlink(), "pam-fixture-already-exists")
        try:
            pwd.getpwnam(USER)
        except KeyError:
            pass
        else:
            raise Failure("fixture-account-already-exists")
        trusted_directory(PRIVATE.parent)
        PRIVATE.mkdir(mode=0o700)
        trusted_directory(PRIVATE, 0o700)
        password = secrets.token_urlsafe(36)
        create_private(PRIVATE / "password", password.encode())
        require(command(["useradd", "--no-create-home", "--shell", "/bin/sh", "--", USER],
                        capture=False)[0] == 0, "fixture-account-create-failed")
        require(command(["chpasswd"], input_text=f"{USER}:{password}\n", capture=False)[0] == 0,
                "fixture-password-setup-failed")
        create_private(PAM, expected_pam)
        # PAM configuration need not be private, but keeping this fixture 0600
        # is sufficient because these pamtester transactions execute as root.
        account = pwd.getpwnam(USER)
        manifest = {"stage": None, "uid": account.pw_uid, "gid": account.pw_gid, "admin": admin}
    else:
        trusted_directory(PRIVATE, 0o700)
        manifest = json.loads(read_private(PRIVATE / "manifest.json"))
        check_stage(stage, manifest["stage"])
        password = read_private(PRIVATE / "password").decode("ascii")
        account = pwd.getpwnam(USER)
        require(account.pw_uid == manifest["uid"] and account.pw_gid == manifest["gid"],
                "fixture-account-changed")
        require(admin == manifest["admin"], "independent-admin-changed")
        require(read_private(PAM) == expected_pam, "pam-fixture-changed")
    require(account.pw_uid != admin["uid"] and account.pw_uid != 0,
            "fixture-account-not-independent")
    check_stage(stage, manifest["stage"])
    report["pam"] = pam_checks(password)
    report["packaged_pam_module"] = str(module)
    report["camera_devices_absent"] = True
    if stage == "candidate-upgrade":
        manifest["retry"] = seed_retry(account.pw_uid)
        available = status(account, recovery=0)
        require(retry_fingerprints(account.pw_uid) == manifest["retry"], "retry-status-altered-fixture")
        # Exercise a real password verification failure when the packaged backend
        # is available, then preserve the daemon-written recovery record. Face
        # counters remain synthetic because no enrollment/capture is performed.
        recovery_failures = 0
        if available:
            wrong, _ = command(["irlume", "retry", "reset", "--user", USER],
                               input_text="wrong-" + password + "\n", capture=False, account=account)
            require(wrong != 0, "retry-wrong-password-accepted")
            status(account, recovery=1)
            recovery_failures = 1
        manifest["recovery_failures"] = recovery_failures
        manifest["retry"] = retry_fingerprints(account.pw_uid)
        report["retry"] = {"face_fixture": "source-validated-synthetic-metadata",
                           "face_failures": 2, "cumulative_face_requests": 7,
                           "recovery_failures": recovery_failures,
                           "recovery_failure_created_by_cli": available,
                           "candidate_status_verified": True,
                           "password_reset_available": available}
    elif stage in ("old-rollback", "candidate-reupgrade"):
        trusted_directory(RETRY, 0o700)
        require(retry_fingerprints(account.pw_uid) == manifest["retry"], "retry-preservation-failed")
        report["retry"] = {"bytes_and_private_modes_preserved": True,
                           "old_version_retry_enforcement": "absent-in-v0.11.3"}
        if stage == "candidate-reupgrade":
            available = status(account, recovery=manifest["recovery_failures"])
            report["retry"]["candidate_status_verified"] = True
            require(retry_fingerprints(account.pw_uid) == manifest["retry"], "retry-status-altered-fixture")
            if available:
                reset = ["irlume", "retry", "reset", "--user", USER]
                wrong, _ = command(reset, input_text="wrong-" + password + "\n",
                                   capture=False, account=account)
                require(wrong != 0, "retry-wrong-password-accepted")
                status(account, recovery=manifest["recovery_failures"] + 1)
                correct, _ = command(reset, input_text=password + "\n",
                                     capture=False, account=account)
                require(correct == 0, "retry-correct-password-refused")
                status(account, strikes=0, budget=0, recovery=0)
                report["retry"]["password_verified_reset"] = "passed-wrong-then-correct"
                report["retry"]["reset_counts_verified_zero"] = True
            else:
                report["retry"]["password_verified_reset"] = "not-available-on-installation"
                report["limitations"].append("candidate-daemon-reports-password-reset-unavailable")
    else:
        report["retry"] = {"old_version_retry_enforcement": "absent-in-v0.11.3"}
    require(admin_identity() == manifest["admin"], "independent-admin-changed")
    report["independent_admin_preserved"] = True
    manifest["stage"] = stage
    save_manifest(manifest)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    report = {"passed": False, "limitations": [
        "synthetic-retry-metadata-is-not-biometric-enrollment-usability",
        "old-release-byte-preservation-is-not-retry-enforcement",
    ]}
    try:
        require(len(args) == 1 and args[0] in STAGES, "invalid-stage")
        report["stage"] = args[0]
        report["virtualization"] = admit_guest()
        run_stage(args[0], report)
        report["passed"] = True
    except Failure as error:
        report["error"] = str(error)
    except Exception:
        # Do not serialize exceptions, subprocess output, account databases,
        # private file content, passwords, or environment into the receipt.
        report["error"] = "internal-check-failed"
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

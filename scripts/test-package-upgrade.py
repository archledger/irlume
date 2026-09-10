#!/usr/bin/env python3
"""Strict 0.11.3 -> 0.12.0 -> 0.11.3 -> 0.12.0 disposable QEMU test.

Run inside a fresh root-owned guest only. Prepare dependencies/package inputs
separately; this script does not alter service security settings. The marker is
an explicit operator attestation, not proof that a VM has no device passthrough.
--output names a NEW JSON file in an existing directory; its sibling .log keeps
raw package-manager and service diagnostics in the guest. Export JSON only.
Failure leaves the current transaction/state intact for inspection; no automatic
removal or repair is attempted. Terminating a timed-out process group cannot
roll back package changes already applied. Synthetic bytes prove preservation, not usable
enrollment, cryptographic rollback, password fallback, or camera functionality.
RPM qualification targets x86_64 Fedora with DNF5 and enforcing SELinux; supply
both --old-selinux and --candidate-selinux for the matching policy packages.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time

MARKER = Path("/run/irlume-upgrade-disposable")
MARKER_BYTES = b"irlume-upgrade-20260910"
INPUT_ROOT = Path("/var/tmp/irlume-upgrade-input")
CONFIG_ROOT = Path("/etc/irlume")
STATE_ROOT = Path("/var/lib/irlume")
SYNTHETIC_ROOT = STATE_ROOT / "upgrade-validation"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin", "LANG": "C", "LC_ALL": "C",
       "DEBIAN_FRONTEND": "noninteractive", "SYSTEMD_PAGER": "cat"}
RPM_QUERY = "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\\n"


class Failure(Exception):
    """Fixed diagnostic codes only: never embed command output or file bytes."""


def require(condition, code):
    if not condition:
        raise Failure(code)


def read_command(argv, timeout=30):
    try:
        result = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure("preflight-command-unavailable-or-timeout") from None
    require(result.returncode == 0, "preflight-command-failed")
    return result.stdout.strip()


def no_symlinks(path):
    require(path.is_absolute() and ".." not in path.parts, "absolute-path-required")
    for item in (*reversed(path.parents), path):
        require(not item.is_symlink(), "symlink-refused")


def admit_guest():
    require(os.geteuid() == 0, "root-required")
    # Unfiltered detection reports the innermost environment. --vm would hide
    # a container inside QEMU and incorrectly admit its shared-kernel boundary.
    kind = read_command(["systemd-detect-virt"])
    require(kind in {"qemu", "kvm"}, "qemu-kvm-required")
    no_symlinks(MARKER)
    require(MARKER.is_file(), "marker-missing")
    require(MARKER.read_bytes() == MARKER_BYTES, "marker-mismatch")
    info = MARKER.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, "marker-not-root-controlled")
    return kind


def package_path(value):
    path = Path(value)
    require(path.is_absolute() and path.is_relative_to(INPUT_ROOT), "input-location")
    no_symlinks(path)
    require(path.is_file(), "package-not-regular")
    return path


def package_format(path):
    if path.name.endswith(".deb"):
        return "deb"
    if path.name.endswith(".pkg.tar.zst"):
        return "arch"
    if path.name.endswith(".rpm"):
        return "rpm"
    raise Failure("unsupported-package-format")


def parse_rpm_metadata(text, package, expected=None):
    fields = text.strip().split("\t")
    require(len(fields) == 5, "rpm-package-metadata")
    name, epoch, version, release, arch = fields
    require(name == package and epoch in {"(none)", "0"}
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
            and (expected is None or version == expected)
            and re.fullmatch(r"[0-9][A-Za-z0-9._+~^]*", release)
            and arch == ("noarch" if package == "irlume-selinux" else "x86_64"),
            "rpm-package-metadata")
    return version + "-" + release


def package_metadata(path, kind, expected, package="irlume"):
    if kind == "rpm":
        return parse_rpm_metadata(read_command(["rpm", "-qp", "--qf", RPM_QUERY, str(path)]),
                                  package, expected)
    if kind == "deb":
        name = read_command(["dpkg-deb", "-f", str(path), "Package"])
        version = read_command(["dpkg-deb", "-f", str(path), "Version"])
        valid = version == expected or re.fullmatch(re.escape(expected) + r"-[0-9]+", version)
    else:
        text = read_command(["tar", "--zstd", "-xOf", str(path), ".PKGINFO"])
        names = re.findall(r"^pkgname = (.+)$", text, re.M)
        versions = re.findall(r"^pkgver = (.+)$", text, re.M)
        require(len(names) == len(versions) == 1, "package-metadata")
        name, version = names[0], versions[0]
        valid = re.fullmatch(re.escape(expected) + r"-[0-9]+", version)
    require(name == "irlume" and valid, "package-metadata")
    return version


def rpm_companions(old_value, candidate_value, versions):
    require(old_value is not None and candidate_value is not None, "rpm-selinux-pair-required")
    paths = (package_path(old_value), package_path(candidate_value))
    require(all(package_format(path) == "rpm" for path in paths), "mixed-package-formats")
    policy_versions = tuple(package_metadata(path, "rpm", expected, "irlume-selinux")
                            for path, expected in zip(paths, ("0.11.3", "0.12.0")))
    require(policy_versions == versions, "rpm-main-policy-version-mismatch")
    return paths


def digest(path):
    hashed = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hashed.update(block)
    return hashed.hexdigest()


def file_record(path):
    info = path.lstat()
    row = {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}
    if stat.S_ISREG(info.st_mode):
        row.update(type="file", sha256=digest(path))
    elif stat.S_ISLNK(info.st_mode):
        row.update(type="symlink", sha256=hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest())
    elif stat.S_ISDIR(info.st_mode):
        row["type"] = "directory"
    else:
        raise Failure("unexpected-file-type")
    return row


def snapshot_tree(root):
    no_symlinks(root)
    require(root.is_dir(), "preserved-directory-missing")
    return {str(path.relative_to(root)): file_record(path)
            for path in (root, *sorted(root.rglob("*")))}


def check_root_state(before, after):
    # tmpfiles intentionally strips group/other access non-recursively. Allow
    # only that change, retaining owner bits, special bits, and ownership.
    require(after["uid"] == before["uid"] and after["gid"] == before["gid"]
            and after["mode"] & ~0o077 == before["mode"] & ~0o077
            and after["mode"] & 0o077 & ~(before["mode"] & 0o077) == 0,
            "state-root-permissions")


def check_cli_version(text, expected):
    require(text.strip() == "irlume " + expected, "cli-version-mismatch")


def check_daemon_identity(pid, running_digest, installed_digest, previous_pid):
    require(pid > 0, "daemon-no-main-pid")
    require(pid != previous_pid, "daemon-not-restarted")
    require(running_digest == installed_digest, "daemon-executable-mismatch")


def check_rollback_payload(baseline, candidate, current, residual, obsolete):
    require(all(path in current and current[path] == row for path, row in baseline.items()),
            "complete-old-payload-rollback-failed")
    require(current.keys() - baseline.keys() <= residual.keys(), "candidate-payload-left-after-rollback")
    for path, row in residual.items():
        require(path in obsolete and path in candidate and path not in baseline
                and Path(path).is_relative_to("/etc") and row == candidate[path],
                "candidate-payload-left-after-rollback")
    return residual


def obsolete_conffiles(text):
    # dpkg-query ${Conffiles}: path, MD5, optional flags. Only an explicit
    # obsolete flag permits an extra retained candidate file after rollback.
    paths = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"\s*(/.*?) ([0-9a-f]{32})(?: (.*))?", line)
        require(match is not None, "invalid-conffile-metadata")
        if match[3] == "obsolete":
            paths.add(match[1])
    return paths


def terminate_group(process, grace=5):
    """Bound teardown by group survival, independently of leader termination."""
    deadline = time.monotonic() + grace
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    while True:
        process.poll()  # Reap our leader so its zombie cannot keep the group alive.
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            break
        time.sleep(min(0.1, remaining))
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        raise Failure("command-teardown-timeout") from None


def ping_ready(timeout):
    # Request::Ping and Response::Pong are serde unit variants, newline framed.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        end = time.monotonic() + timeout
        peer.settimeout(timeout)
        peer.connect("/run/irlume.sock")
        peer.sendall(b'"Ping"\n')
        response = bytearray()
        while b"\n" not in response and len(response) < 256:
            remaining = end - time.monotonic()
            if remaining <= 0:
                return False
            peer.settimeout(remaining)
            block = peer.recv(256 - len(response))
            if not block:
                break
            response.extend(block)
        return bytes(response).strip() == b'"Pong"'


class Runner:
    def __init__(self, log):
        self.log = log

    def command(self, argv, timeout=30, capture=True, check=True):
        self.log.write(("\nCOMMAND " + json.dumps(argv) + "\n").encode())
        self.log.flush()
        try:
            process = subprocess.Popen(
                argv, env=ENV, stdin=subprocess.DEVNULL, start_new_session=True,
                stdout=subprocess.PIPE if capture else self.log, stderr=self.log)
        except OSError:
            raise Failure("command-unavailable") from None
        try:
            output, _ = process.communicate(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            # Also terminate package-manager descendants; never leave an
            # unobserved transaction running after the harness reports failure.
            terminate_group(process)
            if isinstance(error, KeyboardInterrupt):
                raise
            raise Failure("command-timeout") from None
        if output:
            self.log.write(output)
        self.log.write(("\nEXIT " + str(process.returncode) + "\n").encode())
        self.log.flush()
        require(not check or process.returncode == 0, "command-failed")
        return (output or b"").decode("utf-8", errors="replace").strip()

    def install(self, kind, path, stage=None, policy=None):
        if kind == "deb":
            argv = ["apt-get", "-y", "--allow-downgrades", "--no-remove",
                    "-o", "Dpkg::Options::=--force-confdef",
                    "-o", "Dpkg::Options::=--force-confold", "install", str(path)]
        elif kind == "rpm":
            require(policy is not None, "rpm-selinux-pair-required")
            actions = {"old-install": "install", "candidate-upgrade": "upgrade",
                       "old-rollback": "downgrade", "candidate-reupgrade": "upgrade"}
            require(stage in actions, "invalid-rpm-transaction-stage")
            # DNF5 defaults localpkg_gpgcheck to false, independently of the
            # repository signature policy. Require signatures on task inputs.
            argv = ["dnf5", "-y", "--setopt=localpkg_gpgcheck=True",
                    actions[stage], str(path), str(policy)]
        else:
            argv = ["pacman", "-U", "--noconfirm", str(path)]
        self.command(argv, timeout=900, capture=False)

    def stage_check(self, path, label):
        output = self.command([sys.executable, str(path), label], timeout=180)
        try:
            value = json.loads(output)
        except ValueError:
            raise Failure("stage-check-invalid-json") from None
        require(isinstance(value, dict), "stage-check-invalid-json")
        require(value.get("passed") is True, "stage-check-not-passed")
        return value

    def installed_version(self, kind, package="irlume"):
        if kind == "rpm":
            return parse_rpm_metadata(self.command(["rpm", "-q", "--qf", RPM_QUERY, package]), package)
        if kind == "deb":
            text = self.command(["dpkg-query", "-W", "-f=${Status}\t${Version}", "irlume"])
            require(text.startswith("install ok installed\t"), "package-not-configured")
            return text.split("\t", 1)[1]
        text = self.command(["pacman", "-Q", "irlume"])
        require(text.startswith("irlume "), "package-not-installed")
        return text.split(" ", 1)[1]

    def payload(self, kind):
        argv = {"deb": ["dpkg-query", "-L", "irlume"],
                "arch": ["pacman", "-Qlq", "irlume"],
                "rpm": ["rpm", "-ql", "irlume", "irlume-selinux"]}[kind]
        paths = self.command(argv).splitlines()
        rows = {}
        for value in paths:
            path = Path(value)
            require(path.is_absolute() and ".." not in path.parts, "invalid-package-file-list")
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                rows[str(path)] = file_record(path)
        require("/usr/bin/irlume" in rows and "/usr/bin/irlumed" in rows, "package-payload-missing")
        return rows

    def selinux(self):
        require(self.command(["getenforce"]) == "Enforcing", "selinux-not-enforcing")
        modules = self.command(["semodule", "--list-modules"]).splitlines()
        require(any(line.split() == ["irlume"] for line in modules), "selinux-module-not-enabled")
        return {"mode": "Enforcing", "irlume_module_enabled": True}

    def daemon(self, previous_pid, timeout=120):
        installed = digest(Path("/usr/bin/irlumed"))
        end = time.monotonic() + timeout
        last = "daemon-not-ready"
        while time.monotonic() < end:
            try:
                text = self.command(["systemctl", "show", "irlumed.service",
                                     "-p", "ActiveState", "-p", "SubState", "-p", "MainPID"],
                                    timeout=min(5, max(0.1, end - time.monotonic())))
                fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
                require(fields.get("ActiveState") == "active" and fields.get("SubState") == "running",
                        "daemon-not-active")
                pid = int(fields.get("MainPID", "0"))
                running = digest(Path(f"/proc/{pid}/exe"))
                check_daemon_identity(pid, running, installed, previous_pid)
                require(ping_ready(min(2, max(0.1, end - time.monotonic()))), "daemon-not-ready")
                # Confirm Ping did not race a restart or executable replacement.
                current = self.command(["systemctl", "show", "irlumed.service", "-p", "MainPID", "--value"], timeout=5)
                require(current == str(pid) and digest(Path(f"/proc/{pid}/exe")) == installed,
                        "daemon-changed-during-readiness")
                return {"pid": pid, "running_sha256": running, "installed_sha256": installed, "ready": True}
            except (Failure, OSError, ValueError) as error:
                last = str(error) if isinstance(error, Failure) else "daemon-observation-failed"
            time.sleep(min(1, max(0, end - time.monotonic())))
        raise Failure(last)

    def diagnostics(self):
        for argv in (["systemctl", "status", "irlumed.service", "irlumed.socket", "--no-pager", "--full"],
                     ["journalctl", "-u", "irlumed.service", "-n", "150", "--no-pager"]):
            try:
                self.command(argv, capture=False, check=False)
            except Failure:
                self.log.write(b"\nDiagnostics command failed.\n")


def seed_synthetic():
    for root in (CONFIG_ROOT, STATE_ROOT):
        no_symlinks(root)
        require(root.is_dir(), "package-state-directory-missing")
    config = CONFIG_ROOT / "upgrade-validation.conf"
    require(not config.exists() and not config.is_symlink() and not SYNTHETIC_ROOT.exists()
            and not SYNTHETIC_ROOT.is_symlink(), "synthetic-state-already-exists")
    with config.open("xb") as stream:
        stream.write(b"# Synthetic package upgrade validation; no product settings.\n")
    os.chmod(config, 0o600)
    os.chown(config, 0, 0)
    SYNTHETIC_ROOT.mkdir(mode=0o700)
    nested = SYNTHETIC_ROOT / "nested"
    nested.mkdir(mode=0o700)
    for directory in (SYNTHETIC_ROOT, nested):
        os.chown(directory, 0, 0)
    for path in (SYNTHETIC_ROOT / "synthetic-state.bin", nested / "synthetic-retry.bin"):
        with path.open("xb") as stream:
            stream.write(b"IRLUME SYNTHETIC VALIDATION ONLY\x00" + os.urandom(96))
        os.chmod(path, 0o600)
        os.chown(path, 0, 0)


def check_candidate_payload(payload, kind):
    pam = {"deb": "/usr/lib/x86_64-linux-gnu/security/pam_irlume.so",
           "arch": "/usr/lib/security/pam_irlume.so",
           "rpm": "/usr/lib64/security/pam_irlume.so"}[kind]
    modes = {"/usr/libexec/irlume-password-verify": 0o755,
             "/usr/libexec/irlume/irlume-kwallet-init": 0o755,
             "/usr/libexec/irlume/irlume-gkr-unlock": 0o755,
             "/etc/pam.d/irlume-retry-reset": 0o644,
             "/usr/share/polkit-1/actions/org.irlume.enroll.policy": 0o644,
             "/usr/share/polkit-1/actions/org.irlume.recovery-manage.policy": 0o644,
             # nfpm retains the executable bit from the Rust cdylib; Arch
             # explicitly installs the module 0644 in PKGBUILD.
             pam: 0o755 if kind == "deb" else 0o644}
    if kind == "rpm":
        modes["/usr/share/selinux/packages/irlume.pp"] = 0o644
    for path, mode in modes.items():
        row = payload.get(path, {})
        require(row.get("type") == "file" and row.get("mode") == mode
                and row.get("uid") == row.get("gid") == 0, "candidate-required-payload")


def execute(runner, kind, old, candidate, versions, result, stage_check=None, policies=None):
    # A clean guest is essential: do not downgrade an unrelated installation.
    if kind == "rpm":
        require(policies is not None, "rpm-selinux-pair-required")
        installed = runner.command(["rpm", "-qa", "--qf", "%{NAME}\\n"]).splitlines()
        require(not {"irlume", "irlume-selinux"}.intersection(installed), "existing-package-refused")
    else:
        installed = runner.command(["dpkg-query", "-W", "-f=${Status}", "irlume"] if kind == "deb"
                                   else ["pacman", "-Q", "irlume"], check=False)
        require(not installed, "existing-package-refused")
    previous = None
    baseline_payload = candidate_payload = config = synthetic = root = enabled = None
    for label, path, version, cli_version in (
        ("old-install", old, versions[0], "0.11.3"),
        ("candidate-upgrade", candidate, versions[1], "0.12.0"),
        ("old-rollback", old, versions[0], "0.11.3"),
        ("candidate-reupgrade", candidate, versions[1], "0.12.0"),
    ):
        row = {"step": label, "passed": False}
        result["steps"].append(row)
        policy = policies[0 if cli_version == "0.11.3" else 1] if policies else None
        runner.install(kind, path, label, policy)
        require(runner.installed_version(kind) == version, "installed-version-mismatch")
        row["package_version"] = version
        if kind == "rpm":
            policy_version = runner.installed_version(kind, "irlume-selinux")
            require(policy_version == version, "installed-policy-version-mismatch")
            row["selinux_package_version"] = policy_version
            row["selinux"] = runner.selinux()
        check_cli_version(runner.command(["/usr/bin/irlume", "--version"]), cli_version)
        row["cli_version"] = cli_version
        payload = runner.payload(kind)
        row["payload"] = payload
        row["daemon"] = runner.daemon(previous)
        previous = row["daemon"]["pid"]
        row["service_enabled"] = {
            unit: runner.command(["systemctl", "is-enabled", unit], check=False)
            for unit in ("irlumed.service", "irlumed.socket")
        }
        if cli_version == "0.12.0":
            check_candidate_payload(payload, kind)
            candidate_payload = payload
        if label == "old-install":
            baseline_payload = payload
            seed_synthetic()
            config = snapshot_tree(CONFIG_ROOT)
            synthetic = snapshot_tree(SYNTHETIC_ROOT)
            root = file_record(STATE_ROOT)
            enabled = row["service_enabled"]
            result["preservation_baseline"] = {"config": config, "synthetic": synthetic, "state_root": root}
        else:
            require(row["service_enabled"] == enabled, "service-enabled-state-changed")
            require(snapshot_tree(CONFIG_ROOT) == config, "configuration-preservation-failed")
            require(snapshot_tree(SYNTHETIC_ROOT) == synthetic, "synthetic-preservation-failed")
            current_root = file_record(STATE_ROOT)
            check_root_state(root, current_root)
            root = current_root
            if label == "old-rollback":
                # dpkg keeps obsolete conffiles in both its status database and
                # file list. Preserve exact baseline entries and permit only
                # explicitly declared obsolete candidate /etc files as extras.
                obsolete = obsolete_conffiles(runner.command(
                    ["dpkg-query", "-W", "-f=${Conffiles}", "irlume"])) if kind == "deb" else set()
                residual = {}
                for value in (candidate_payload.keys() | payload.keys()) - baseline_payload.keys():
                    path = Path(value)
                    if path.exists() or path.is_symlink():
                        residual[value] = file_record(path)
                row["retained_candidate_conffiles"] = check_rollback_payload(
                    baseline_payload, candidate_payload, payload, residual, obsolete)
        row["state_root"] = root
        if stage_check is not None:
            row["auth_check"] = runner.stage_check(stage_check, label)
        row["passed"] = True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--stage-check", help="Optional trusted Python checker emitting credential-free JSON with passed=true")
    parser.add_argument("--old-selinux", help="RPM only: matching old irlume-selinux package")
    parser.add_argument("--candidate-selinux", help="RPM only: matching candidate irlume-selinux package")
    args = parser.parse_args(argv)
    # No log, output, fixture or package write before all admission checks.
    try:
        kind_vm = admit_guest()
        old, candidate = package_path(args.old), package_path(args.candidate)
        stage_check = package_path(args.stage_check) if args.stage_check else None
        kind = package_format(old)
        require(package_format(candidate) == kind, "mixed-package-formats")
        versions = (package_metadata(old, kind, "0.11.3"), package_metadata(candidate, kind, "0.12.0"))
        policies = None
        if kind == "rpm":
            policies = rpm_companions(args.old_selinux, args.candidate_selinux, versions)
            require(read_command(["getenforce"]) == "Enforcing", "selinux-not-enforcing")
        else:
            require(args.old_selinux is None and args.candidate_selinux is None, "selinux-options-require-rpm")
        output = Path(args.output)
        log_path = output.with_name(output.name + ".log")
        for path in (output, log_path):
            no_symlinks(path)
            require(path.parent.is_dir() and not path.exists(), "new-output-required")
    except (Failure, OSError) as error:
        print("REFUSED: " + (str(error) if isinstance(error, Failure) else "preflight-filesystem-error"), file=sys.stderr)
        return 2
    os.umask(0o077)
    result = {"schema": 1, "passed": False, "vm": kind_vm, "format": kind, "steps": [],
              "auth_stage_check_supplied": stage_check is not None,
              "scope": "synthetic byte/mode/owner preservation only; no enrollment usability or password fallback claim",
              "package_sha256": {"old": digest(old), "candidate": digest(candidate)}}
    if policies:
        result["package_sha256"].update(old_selinux=digest(policies[0]), candidate_selinux=digest(policies[1]))
    with output.open("x") as report, log_path.open("xb") as log:
        runner = Runner(log)
        try:
            execute(runner, kind, old, candidate, versions, result, stage_check, policies)
            result["passed"] = True
        except (Failure, OSError, ValueError, KeyboardInterrupt) as error:
            result["failure"] = str(error) if isinstance(error, Failure) else "harness-operation-failed"
        finally:
            runner.diagnostics()
            json.dump(result, report, indent=2, sort_keys=True)
            report.write("\n")
    print("PASS" if result["passed"] else "FAIL; inspect guest-local JSON and log")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

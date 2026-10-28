"""Strict native NPU experiment. Run only inside the named disposable guest."""

import hashlib
import json
import os
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

PAYLOAD = Path("/mnt/payload")
OUT = Path("/mnt/evidence")
AUDIT = "/usr/local/libexec/irlume-aa/auditctl"
units = []
records = []
used = 0
current = "setup"
last_output = ""


def save(name, value):
    global used
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    data = text.encode()
    if (
        Path(name).name != name
        or len(data) > 256 * 1024
        or used + len(data) > 8 * 1024**2
    ):
        raise RuntimeError("evidence bound exceeded")
    with (OUT / name).open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    used += len(data)


def run(args, timeout=20, check=True, maximum=256 * 1024):
    global last_output
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    reader = selectors.DefaultSelector()
    reader.register(process.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while reader.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("command deadline")
            for key, _ in reader.select(0.1):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    reader.unregister(key.fileobj)
                else:
                    data.extend(chunk)
                    if len(data) > maximum:
                        del data[maximum:]
                        raise RuntimeError("command output bound exceeded")
        code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    finally:
        last_output = data.decode(errors="replace")
        reader.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    if check and code != 0:
        raise RuntimeError(f"command exit {code}: {args[0]}")
    return code, last_output


def lost():
    _, text = run([AUDIT, "-s"])
    return int(
        dict(
            line.split(None, 1)
            for line in text.splitlines()
            if len(line.split(None, 1)) == 2
        )["lost"]
    )


def cache_snapshot(case):
    root = Path("/var/cache/irlume/npu") / case
    rows = []
    total = 0
    seen = 0
    deadline = time.monotonic() + 10
    if root.exists():
        for path in root.rglob("*"):
            seen += 1
            if seen > 512 or len(rows) >= 256 or time.monotonic() > deadline:
                raise RuntimeError("cache inventory bound exceeded")
            if path.is_symlink():
                raise RuntimeError("unexpected cache alias")
            if path.is_file():
                size = path.stat().st_size
                total += size
                if size > 256 * 1024**2 or total > 512 * 1024**2:
                    raise RuntimeError("cache data bound exceeded")
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                rows.append(
                    {
                        "path": str(path.relative_to(root)),
                        "bytes": path.stat().st_size,
                        "sha256": digest,
                        "mode": oct(path.stat().st_mode & 0o777),
                    }
                )
    return sorted(rows, key=lambda row: row["path"])


def check_install_space():
    usage = shutil.disk_usage("/")
    # Installation plus two bounded case caches and filesystem working space.
    required = 2 * 1024**3
    if usage.free < required:
        raise RuntimeError(
            f"guest root free space {usage.free} is below required {required} bytes"
        )
    return {
        "total_bytes": usage.total,
        "free_bytes": usage.free,
        "required_free_bytes": required,
    }


def install():
    space = check_install_space()
    save("root-space.json", space)
    manifest = json.loads((PAYLOAD / "manifest.json").read_text())
    for name, digest in manifest["files"].items():
        path = PAYLOAD / name
        if path.is_symlink() or not path.resolve().is_relative_to(PAYLOAD):
            raise RuntimeError("invalid payload path")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise RuntimeError("payload checksum mismatch")
    for name in ("/usr/bin/irlumed", "/usr/local/bin/irlumed"):
        if Path(name).exists():
            raise RuntimeError("guest already has a daemon")
        Path(name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PAYLOAD / "bin/vision-test", name)
        Path(name).chmod(0o755)
    for name in manifest["native_files"]:
        if not name.startswith("usr/lib64/") or ".." in Path(name).parts:
            raise RuntimeError("unexpected native destination")
        destination = Path("/") / name
        if destination.exists() or destination.is_symlink():
            raise RuntimeError("pre-existing native destination")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(PAYLOAD / "tree" / name, destination)
        destination.chmod(0o644)
    for name, target in manifest["aliases"].items():
        if (
            not name.startswith("usr/lib64/")
            or ".." in Path(name).parts
            or Path(target).name != target
        ):
            raise RuntimeError("unexpected native alias")
        destination = Path("/") / name
        if destination.exists() or destination.is_symlink():
            raise RuntimeError("pre-existing native alias")
        destination.symlink_to(target)
    copies = {
        "models/glintr100.onnx": "/usr/share/irlume/models/glintr100.onnx",
        "ort/libonnxruntime.so.1.28.1": "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1",
        "ort/libonnxruntime_providers_shared.so": "/opt/irlume/onnxruntime/lib/libonnxruntime_providers_shared.so",
        "audit/auditctl": AUDIT,
        "audit/libauparse.so.0": "/usr/lib/x86_64-linux-gnu/libauparse.so.0",
    }
    for relative, name in copies.items():
        destination = Path(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise RuntimeError("pre-existing fixed payload destination")
        shutil.copyfile(PAYLOAD / relative, destination)
        destination.chmod(0o755 if name == AUDIT else 0o644)
    (Path("/opt/irlume/onnxruntime/lib") / "libonnxruntime.so.1").symlink_to(
        "libonnxruntime.so.1.28.1"
    )
    with Path("/etc/ld.so.conf.d/irlume-aa-native.conf").open("x") as config:
        config.write(
            "/usr/lib64\n/usr/lib64/openvino-2026.2.1\n/opt/irlume/onnxruntime/lib\n"
        )
    run(["ldconfig"])
    if not os.path.ismount("/sys/kernel/debug"):
        run(["mount", "-t", "debugfs", "debugfs", "/sys/kernel/debug"])
    run(["modprobe", "intel_vpu"])
    run([AUDIT, "-e", "1"])
    if lost() != 0:
        raise RuntimeError("audit already lost records")
    Path("/var/cache/irlume/npu").mkdir(parents=True, exist_ok=True)
    Path("/opt/irlume-aa-denied").write_text(
        "audit visibility control, not native code\n"
    )
    sys.path.insert(0, str(PAYLOAD / "inspector-vendor"))
    sys.path.insert(0, str(PAYLOAD / "helpers"))
    return manifest["native_lookups"]


def execute(case, control, environment):
    from irlume_1046_native_preflight import validate_environment

    validate_environment(environment)
    executable = (
        "/usr/bin/irlumed" if case == "bin-native" else "/usr/local/bin/irlumed"
    )
    kind = "control" if control else "native"
    unit = f"irlume-aa-{case}-{kind}"
    units.append(unit)
    test = (
        "npu_apparmor_hw_audit_control"
        if control
        else "npu_apparmor_hw_native_recognizer"
    )
    properties = [
        "RuntimeMaxSec=90",
        "MemoryMax=3G",
        "CPUQuota=200%",
        "TasksMax=256",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectKernelTunables=yes",
        "ReadWritePaths=/var/cache/irlume/npu",
        "DevicePolicy=closed",
        "DeviceAllow=/dev/accel/accel0 rw",
        "CapabilityBoundingSet=",
        "PrivateTmp=yes",
        "LimitCORE=0",
    ]
    args = [
        "systemd-run",
        "--wait",
        "--pipe",
        "--collect",
        "--service-type=exec",
        "--unit=" + unit,
    ]
    for item in properties:
        args += ["--property=" + item]
    args += [
        "/usr/bin/env",
        "-i",
        *[f"{key}={value}" for key, value in environment.items()],
        executable,
        "--ignored",
        "--exact",
        "onnx::npu_tests::npu_apparmor::" + test,
        "--test-threads=1",
        "--nocapture",
    ]
    code, output = run(args, timeout=105, check=False)
    save(f"{case}-{kind}-stdout.txt", output)
    _, state = run(
        ["systemctl", "show", unit + ".service", "-p", "ActiveState", "-p", "MainPID"]
    )
    fields = dict(line.split("=", 1) for line in state.splitlines())
    if fields.get("MainPID") != "0" or fields.get("ActiveState") not in (
        "inactive",
        "failed",
    ):
        raise RuntimeError("preceding test service has not terminated")
    return code, output


def case_run(case, seeds):
    global current
    from irlume_1046_native_audit import validate_window
    from irlume_1046_native_preflight import guest_closure
    from irlume_1046_native_result import parse_native_result, require_single_test

    current = case
    policy = "usr.bin.irlumed" if case == "bin-native" else "usr.local.bin.irlumed"
    path = "/etc/apparmor.d/" + policy
    shutil.copyfile(PAYLOAD / "profiles" / policy, path)
    _, expanded = run(["apparmor_parser", "--preprocess", path])
    save(case + "-expanded-policy.txt", expanded)
    run(["apparmor_parser", "-QK", path])
    run(["apparmor_parser", "-r", path])
    executable = (
        "/usr/bin/irlumed" if case == "bin-native" else "/usr/local/bin/irlumed"
    )
    reference = "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1"
    shared = "/opt/irlume/onnxruntime/lib/libonnxruntime_providers_shared.so"
    lookups = [
        *seeds,
        {"lookup": reference, "canonical": reference},
        {"lookup": shared, "canonical": shared},
        {"lookup": "libonnxruntime_providers_shared.so", "canonical": shared},
        {
            "lookup": "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1",
            "canonical": reference,
        },
        {"lookup": "libonnxruntime.so.1", "canonical": reference},
    ]
    closure = guest_closure(executable, lookups)
    save(case + "-closure.json", closure)
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "HOME": "/",
        "ORT_DYLIB_PATH": "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1",
        "IRLUME_NPU_AA_CASE": case,
    }
    for control in (True, False):
        kind = "control" if control else "native"
        if lost() != 0:
            raise RuntimeError("audit loss before case")
        _, latest = run(["journalctl", "-n", "1", "-o", "json"])
        cursor = json.loads(latest.splitlines()[-1])["__CURSOR"]
        code, output = execute(case, control, environment)
        run(["journalctl", "--sync"])
        _, journal = run(["journalctl", "--after-cursor", cursor, "-o", "json"])
        save(f"{case}-{kind}-journal.jsonl", journal)
        if lost() != 0:
            raise RuntimeError("audit loss after case")
        if control:
            matches = re.findall(
                r"NATIVE_AA_DENIAL_CONTROL pid=(\d+) tid=(\d+)", output
            )
            require_single_test(output, code)
            if len(matches) != 1:
                raise RuntimeError("denial control did not pass")
            pid, tid = map(int, matches[0])
            denied = validate_window(journal, control_pid=pid)
            save(
                case + "-control.json",
                {
                    "pid": pid,
                    "tid": tid,
                    "denials": denied,
                    "lost": 0,
                },
            )
        else:
            validate_window(journal)
            result = parse_native_result(output, code, case)
            if guest_closure(executable, lookups) != closure:
                raise RuntimeError("native inputs changed during the run")
            save(case + "-result.json", result)
            save(case + "-cache.json", cache_snapshot(case))
            records.append(result)


def main():
    if (
        os.geteuid() != 0
        or platform.node() != "irlume-aa-native"
        or not os.path.ismount(OUT)
    ):
        raise RuntimeError("refusing execution outside the named guest")
    seeds = install()
    for case in ("bin-native", "local-native"):
        case_run(case, seeds)
    return {
        "passed": 2,
        "controls_passed": 2,
        "scope": "test-only-native",
        "native_inferences": 12,
    }


if __name__ == "__main__":
    summary = {}
    try:
        if (
            os.geteuid() != 0
            or platform.node() != "irlume-aa-native"
            or not os.path.ismount(OUT)
        ):
            raise SystemExit("not the disposable guest")
        signal.signal(
            signal.SIGALRM,
            lambda *_: (_ for _ in ()).throw(TimeoutError("guest deadline")),
        )
        signal.alarm(max(1, 300 - int(time.monotonic())))
        summary = main()
    except (
        OSError,
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        ImportError,
        subprocess.SubprocessError,
    ) as error:
        summary = {
            "error": str(error),
            "active_case": current,
            "completed_cases": len(records),
        }
        save("failure-output.txt", last_output)
    finally:
        signal.alarm(0)
        for unit in units:
            try:
                run(["systemctl", "stop", unit + ".service"], timeout=12, check=False)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                summary["cleanup_error"] = str(error)
        if "error" in summary and current in ("bin-native", "local-native"):
            try:
                save("failed-cache.json", cache_snapshot(current))
            except (OSError, ValueError, RuntimeError) as error:
                summary["cache_capture_error"] = str(error)
        if summary:
            save("summary.json", summary)
            print("NATIVE_AA_SUMMARY " + json.dumps(summary), flush=True)
    raise SystemExit(
        0 if summary.get("passed") == 2 and "cleanup_error" not in summary else 1
    )

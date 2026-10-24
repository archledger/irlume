#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Execute trusted test binaries in an empty-root, hardware-free namespace.

Requires bubblewrap, a C compiler and pax-utils' Python lddtree. The optional
IRLUME_TEST_LDDTREE and IRLUME_TEST_ELFTOOLS_WHEEL paths select locally pinned
test tools. This runner never installs tools or falls back to host execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
FORBIDDEN = ("onnxruntime", "openvino", "tensorflow", "litert", "level-zero", "intel-opencl")


def checked_file(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("test inputs must use absolute paths")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
        raise ValueError("test input must be an owned non-writable regular file")
    return path.resolve()


def dependencies(binary):
    inspector = os.environ.get("IRLUME_TEST_LDDTREE") or shutil.which("lddtree")
    if not inspector:
        raise RuntimeError("pax-utils lddtree is required; no host fallback")
    inspector = checked_file(inspector)
    env = {"PATH": os.defpath, "LANG": "C"}
    wheel = os.environ.get("IRLUME_TEST_ELFTOOLS_WHEEL")
    if wheel:
        env["PYTHONPATH"] = str(checked_file(wheel))
    result = subprocess.run([sys.executable, str(inspector), "--list", str(binary)],
                            env=env, capture_output=True, text=True, timeout=20, check=True,
                            stdin=subprocess.DEVNULL, close_fds=True)
    paths = result.stdout.splitlines()
    if result.stderr or not paths or Path(paths[0]).resolve() != binary.resolve():
        raise RuntimeError("incomplete dependency inspection")
    return paths[1:]


def run(subject, cli, arguments, receipt):
    name = Path(subject).name
    subject = checked_file(subject)
    with tempfile.TemporaryDirectory(prefix="irlume-isolated-cli-") as temporary:
        root = Path(temporary)
        probe = root / "probe"
        compiler = shutil.which("cc")
        if not compiler:
            raise RuntimeError("a C compiler is required; no host fallback")
        subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                        str(HERE / "isolated-cli-probe.c"), "-o", str(probe)], check=True,
                       stdin=subprocess.DEVNULL, capture_output=True, close_fds=True, timeout=60)
        files = {"/work/subject": subject, "/work/probe": checked_file(probe)}
        if cli:
            files["/work/irlume"] = checked_file(cli)
        for binary in list(files.values()):
            for path in dependencies(binary):
                if not Path(path).is_absolute() or any(word in path.lower() for word in FORBIDDEN):
                    raise RuntimeError("unresolved or forbidden test dependency")
                files[path] = checked_file(path)
        state = root / "state"
        state.mkdir(mode=0o700)
        for directory in ["config", "data", "tmp"]:
            (state / directory).mkdir(mode=0o700)
        (root / "passwd").write_text(f"fixture:x:{os.getuid()}:{os.getgid()}:fixture:/home/fixture:/bin/false\n")
        (root / "group").write_text(f"fixture:x:{os.getgid()}:\n")
        (root / "nsswitch.conf").write_text("passwd: files\ngroup: files\n")
        bwrap = shutil.which("bwrap")
        if not bwrap:
            raise RuntimeError("bubblewrap is required; no host fallback")
        command = [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
                   "--cap-drop", "ALL", "--tmpfs", "/", "--proc", "/proc", "--dev", "/dev",
                   "--dir", "/sys", "--dir", "/run", "--dir", "/etc", "--dir", "/var",
                   "--dir", "/home/fixture", "--dir", "/tmp", "--dir", "/work",
                   "--bind", str(state), "/work/state"]
        for destination, source in sorted(files.items()):
            command += ["--ro-bind", str(source), destination]
        for path in ["passwd", "group", "nsswitch.conf"]:
            command += ["--ro-bind", str(root / path), "/etc/" + path]
        environment = {"HOME": "/home/fixture", "TMPDIR": "/work/state/tmp", "PATH": "/nonexistent",
                       "LANG": "C", "LC_ALL": "C", "IRLUME_SOCKET": "/work/state/no-daemon.sock",
                       "IRLUME_CONFIG_DIR": "/work/state/config", "IRLUME_STATE_DIR": "/work/state/data",
                       "ASAN_OPTIONS": "detect_stack_use_after_return=1",
                       "IRLUME_SANDBOX_ARGV0": name, "IRLUME_PROVENANCE_TEST_CLI": "/work/irlume"}
        for key, value in environment.items():
            command += ["--setenv", key, value]
        command += ["--chdir", "/work/state", "--", "/work/probe", "/work/subject", *arguments]
        result = subprocess.run(command, env={"PATH": os.defpath}, close_fds=True,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        evidence = {"returncode": result.returncode, "mounts": {
            dest: {"source": str(src), "sha256": hashlib.sha256(src.read_bytes()).hexdigest()}
            for dest, src in files.items()}}
        preflight = state / "preflight.json"
        evidence["preflight"] = json.loads(preflight.read_text()) if preflight.exists() else None
        receipt.write_text(json.dumps(evidence, indent=2) + "\n")
        if evidence["preflight"] is None:
            raise RuntimeError(
                f"sandbox preflight did not complete (status {result.returncode}); "
                f"no host fallback: {result.stderr[:4096]!r}"
            )
        return result


def check_documents(output, schema_path):
    import jsonschema
    schema = json.loads(schema_path.read_text())
    validator = jsonschema.validators.validator_for(schema)(schema)
    found = set()
    for line in output.decode().splitlines():
        if "PROVENANCE_DOCUMENT " not in line:
            continue
        item = json.loads(line.split("PROVENANCE_DOCUMENT ", 1)[1])
        key = (item["case"], item["command"])
        if key in found:
            raise RuntimeError("duplicate provenance document")
        found.add(key)
        validator.validate(item["output"])
    expected = {(case, command) for case in ["present", "legacy", "future", "malformed", "unknown-placement"]
                for command in ["status", "doctor"]}
    if found != expected:
        raise RuntimeError("missing positive provenance documents")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    result = run(args.subject, args.cli, arguments, args.receipt)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    if result.returncode == 0 and args.schema:
        check_documents(result.stdout, args.schema)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Explicit, fixture-only static bootstrap runner. Never executes on the host."""
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import struct
import subprocess
import time
import tomllib

LIMIT = 1024 * 1024
TARGET = "x86_64-unknown-linux-musl"
VERSIONS = {"libc": "0.2.191", "sha2": "0.11.1"}
ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "crates/irlume-common/examples"
FLAGS = ["--edition=2021", "--target", TARGET, "--cfg", "irlume_hw_evidence",
         "--check-cfg", "cfg(irlume_hw_evidence)", "--check-cfg", "cfg(test)",
         "-Dwarnings", "-Wunexpected_cfgs",
         "-Ctarget-feature=+crt-static", "-Crelocation-model=static", "-Clink-arg=-no-pie",
         "-Copt-level=z", "-Cdebuginfo=0", "-Cstrip=symbols", "-Clto=fat", "-Ccodegen-units=1"]
LINTS = ["-Wclippy::missing_errors_doc", "-Wclippy::missing_panics_doc",
         "-Wclippy::undocumented_unsafe_blocks"]
_OWNED = {}


def package_id(name, version):
    return f"registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"


def select_artifacts(rows, output):
    """Select only exact, successful, confined, non-test target-library outputs."""
    finished = [row for row in rows if row.get("reason") == "build-finished"]
    if len(finished) != 1 or finished[0].get("success") is not True:
        raise ValueError("unsuccessful build transaction")
    expected = output.resolve() / TARGET / "release"
    result = {}
    for name, version in VERSIONS.items():
        candidates = [row for row in rows if row.get("reason") == "compiler-artifact"
                      and row.get("package_id") == package_id(name, version)
                      and row.get("target", {}).get("kind") == ["lib"]
                      and row.get("target", {}).get("name") == name
                      and row.get("profile", {}).get("test") is False]
        if len(candidates) != 1:
            raise ValueError("missing or ambiguous dependency artifact")
        row = candidates[0]
        if row.get("fresh") is not False:
            raise ValueError("stale or incomplete dependency transaction")
        libraries = [Path(path) for path in row["filenames"] if path.endswith(".rlib")]
        if len(libraries) != 1:
            raise ValueError("missing or ambiguous rlib")
        try:
            path = libraries[0].resolve(strict=True)
        except OSError as error:
            raise ValueError("missing dependency artifact") from error
        if path.parent not in (expected, expected / "deps") or not path.is_file():
            raise ValueError("dependency artifact outside transaction")
        result[name] = {"path": str(path), "package_id": row["package_id"],
                        "features": row["features"], "sha256": digest(path)}
    return result


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Build:
    """One explicit build transaction with fresh dependency and variant outputs."""

    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        lints = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["lints"]
        # A new workspace lint must be carried into this direct invocation,
        # never silently omitted just because Cargo is not compiling examples.
        if lints["clippy"] != {flag.removeprefix("-Wclippy::"): "warn" for flag in LINTS}:
            raise RuntimeError("workspace Clippy lint policy changed; update the fixture lane")
        if lints["rust"] != {"unexpected_cfgs": {"level": "warn", "check-cfg": ["cfg(irlume_hw_evidence)"]}}:
            raise RuntimeError("workspace Rust lint policy changed; update the fixture lane")
        self.environment = {key: os.environ[key] for key in
                            ("PATH", "HOME", "RUSTUP_HOME", "CARGO_HOME") if key in os.environ}
        self.environment.update(CARGO_BUILD_JOBS="2", CARGO_PROFILE_RELEASE_DEBUG="0",
                                CARGO_PROFILE_RELEASE_OPT_LEVEL="z")
        self.rustup = shutil.which("rustup")
        self.cargo = shutil.which("cargo")
        if not self.rustup or not self.cargo:
            raise RuntimeError("installed Rust tools required")
        identity = self.command("rustc-identity", [self.rustup, "run", "1.88.0", "rustc", "-vV"])
        if not identity.stdout.startswith("rustc 1.88.0 "):
            raise RuntimeError("wrong rustc")
        output = self.directory / "dependencies"
        env = dict(self.environment, CARGO_TARGET_DIR=str(output),
                   RUSTFLAGS=" ".join(FLAGS[FLAGS.index("-Ctarget-feature=+crt-static"):]))
        command = [self.cargo, "+1.88.0", "build", "--offline", "--locked", "--release",
                   "--target", TARGET, "--message-format=json"]
        for name, version in VERSIONS.items():
            command.extend(["-p", f"{name}@{version}"])
        built = self.command("dependencies", command, env=env)
        rows = [json.loads(line) for line in built.stdout.splitlines()]
        self.artifacts = select_artifacts(rows, output)
        self.search = ["-Ldependency=" + str(output / TARGET / "release/deps"),
                       "-Ldependency=" + str(output / "release/deps")]
        for name, artifact in self.artifacts.items():
            self.search += ["--extern", name + "=" + artifact["path"]]
        sources = {str(path.relative_to(ROOT)): digest(path) for path in
                   sorted(EXAMPLES.rglob("*.rs"))}
        sources.update({str(path.relative_to(ROOT)): digest(path) for path in
                        (Path(__file__).resolve(), Path(__file__).with_name("test-measurement-fixture-bootstrap.py").resolve(),
                         ROOT / "scripts/test-measurement-fixture-bootstrap.sh",
                         ROOT / "scripts/ci/isolated-cli.py", ROOT / "scripts/ci/isolated-cli-probe.c")})
        sources.update({"Cargo.lock": digest(ROOT / "Cargo.lock"),
                        "Cargo.toml": digest(ROOT / "Cargo.toml")})
        self.record = {"compiler": identity.stdout, "kernel": os.uname().release,
                       "machine": os.uname().machine, "dependencies": self.artifacts,
                       "sources": sources, "flags": FLAGS, "lints": LINTS,
                       "search": self.search, "variants": {}}
        self.save()

    def command(self, label, command, *, env=None, failure=False):
        result = subprocess.run(command, cwd=ROOT, env=env or self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                close_fds=True, timeout=180)
        (self.directory / (label + ".log")).write_text(
            json.dumps(command) + "\n" + result.stdout + result.stderr)
        if (result.returncode == 0) == failure:
            raise RuntimeError(f"unexpected build/lint result: {label}; see transaction log")
        return result

    def save(self):
        (self.directory / "manifest.json").write_text(json.dumps(self.record, indent=2) + "\n")

    def negative_controls(self):
        active = '#[cfg(all(irlume_hw_evidence, target_os="linux", target_env="musl", target_feature="crt-static"))]\n'
        for name, source, expected in [
            ("active_compile_negative", active + 'compile_error!("active-control");\nfn main() {}\n', ["active-control"]),
            ("active_lint_negative", active + 'pub mod checks {\n'
             'pub fn errors() -> Result<(), std::io::Error> { Ok(()) }\n'
             'pub fn panics() { panic!("test"); }\n'
             'pub fn memory() { unsafe { std::ptr::read_volatile(&0); } }\n}\nfn main() {}\n',
             ["missing_errors_doc", "missing_panics_doc", "undocumented_unsafe_blocks"]),
        ]:
            path = self.directory / (name + ".rs")
            path.write_text(source)
            command = [self.rustup, "run", "1.88.0", "clippy-driver", str(path), *FLAGS,
                       *self.search, *LINTS, "--emit=metadata", "-o", str(path.with_suffix(".rmeta"))]
            result = self.command(name, command, failure=True)
            if not all(item in result.stderr for item in expected):
                raise RuntimeError("negative control failed for the wrong reason")
            self.record.setdefault("controls", {})[name] = {
                "source_sha256": digest(path), "status": result.returncode, "expected": expected}
        self.save()

    def compile(self, name, source, *, pin=None, mode=None, fault=None, test=False,
                evidence=True, target=TARGET, pie=False, dynamic=False, document=False):
        self.check_inputs()
        variant = self.directory / name
        variant.mkdir(mode=0o700)
        output = variant / "program"
        env = dict(self.environment)
        for key, value in (("IRLUME_FIXTURE_SHA256", pin), ("IRLUME_FIXTURE_MODE", mode),
                           ("IRLUME_BOOTSTRAP_TEST", fault)):
            if value is not None:
                env[key] = value
        flags = list(FLAGS)
        if not evidence:
            at = flags.index("--cfg")
            del flags[at:at + 2]
        flags[flags.index("--target") + 1] = target
        if pie or dynamic:
            flags[flags.index("-Crelocation-model=static")] = "-Crelocation-model=pic"
            flags[flags.index("-Clink-arg=-no-pie")] = "-Clink-arg=-pie" if dynamic else "-Clink-arg=-static-pie"
        if dynamic:
            flags[flags.index("-Ctarget-feature=+crt-static")] = "-Ctarget-feature=-crt-static"
        # GNU stubs intentionally do not resolve or import musl dependencies.
        search = self.search if target == TARGET else []
        args = [str(source), *flags, *search, "-o", str(output)]
        if test:
            args.append("--test")
        lint_args = list(args)
        lint_args[lint_args.index("-o") + 1] = str(variant / "lint.rmeta")
        self.command(name + "-clippy", [self.rustup, "run", "1.88.0", "clippy-driver",
                                      *lint_args, *LINTS, "--emit=metadata"], env=env)
        # Use rustc as well; successful metadata/lint is not a link acceptance.
        self.command(name + "-rustc", [self.rustup, "run", "1.88.0", "rustc", *args], env=env)
        if document:
            doc_args = [str(source), *flags, *search, "--document-private-items", "--crate-type", "bin",
                        "--out-dir", str(variant / "docs")]
            if test:
                doc_args += ["--cfg", "test"]
            self.command(name + "-rustdoc", [self.rustup, "run", "1.88.0", "rustdoc", *doc_args], env=env)
        self.check_inputs()
        if target == TARGET and not pie and not dynamic:
            static_elf(output.read_bytes())
        if source.name == "measurement_entry_probe.rs" and output.stat().st_size > LIMIT:
            raise RuntimeError("oversized fixture; pin not accepted")
        self.record["variants"][name] = {"sha256": digest(output), "pin": pin,
                                        "source": str(source), "mode": mode, "fault": fault,
                                        "size": output.stat().st_size, "args": args,
                                        "documented": document}
        self.save()
        return output

    def check_inputs(self):
        for path, expected in self.record["sources"].items():
            if digest(ROOT / path) != expected:
                raise RuntimeError("source changed during the build transaction")
        for artifact in self.artifacts.values():
            if digest(artifact["path"]) != artifact["sha256"]:
                raise RuntimeError("dependency changed during the build transaction")


def static_elf(data):
    """Check the deliberately narrow ELF64, x86-64, static ET_EXEC profile."""
    if not 64 <= len(data) <= 16 * LIMIT or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("elf-header")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    phoff = struct.unpack_from("<Q", data, 32)[0]
    ehsize, phsize, phnum = struct.unpack_from("<HHH", data, 52)
    if (kind, machine, version, ehsize, phsize) != (2, 62, 1, 64, 56):
        raise ValueError("elf-profile")
    if not phnum or phnum > 128 or phoff < 64 or phoff + phnum * 56 > len(data):
        raise ValueError("elf-table")
    load = False
    for offset in range(phoff, phoff + phnum * 56, 56):
        segment, = struct.unpack_from("<I", data, offset)
        if segment in (2, 3):
            raise ValueError("elf-dynamic")
        load |= segment == 1
    if not load:
        raise ValueError("elf-load")


def namespace_command(bwrap, executable, sync_fd=None, seccomp_fd=None, extra_environment=None,
                      cwd="/"):
    command = [str(bwrap), "--unshare-all", "--as-pid-1", "--die-with-parent",
               "--clearenv", "--cap-drop", "ALL", "--tmpfs", "/", "--proc", "/proc",
               "--dir", "/dev", "--dev-bind", "/dev/null", "/dev/null",
               "--ro-bind", str(executable), "/bootstrap", "--chdir", cwd]
    for key, value in (extra_environment or {}).items():
        command += ["--setenv", key, value]
    if sync_fd is not None:
        command += ["--sync-fd", str(sync_fd)]
    if seccomp_fd is not None:
        command += ["--seccomp", str(seccomp_fd)]
    return command + ["--", "/bootstrap"]


def owned_static(path):
    path = Path(path).resolve(strict=True)
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022
            or not 64 <= info.st_size <= 16 * LIMIT):
        raise ValueError("bootstrap must be a private owned regular file")
    data = path.read_bytes()
    static_elf(data)
    return path, hashlib.sha256(data).hexdigest()


def _finish(process):
    """Keep an unreaped group leader and pipe handles until kill/EOF/reap finish.

    On failure, _OWNED retains the process and handles for explicit recovery.
    No other child or process group is inspected or signalled.
    """
    if process.returncode is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    pending = [stream for stream in (process.stdout, process.stderr)
               if stream is not None and not stream.closed]
    deadline = time.monotonic() + 2
    while pending:
        if time.monotonic() >= deadline:
            raise TimeoutError("fixture cleanup did not reach EOF; ownership retained")
        ready, _, _ = select.select(pending, [], [], 0.05)
        for stream in ready:
            if not os.read(stream.fileno(), 4096):
                pending.remove(stream)
    process.wait(timeout=max(0.001, deadline - time.monotonic()))
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()
    _OWNED.pop(process.pid, None)


def run(executable, source, *, timeout=3.0, sync_fd=None, seccomp_fd=None, result_fd=None,
        diagnostic_fd=None, cancel=None, on_chunk=None, extra_environment=None, cwd="/"):
    """Run only in a new namespace; kill/reap the owned group before returning.

    Optional descriptors are private test controls, never a runtime pin or
    launcher interface. A cancellation callback raises to exercise cleanup.
    """
    executable, identity = owned_static(executable)
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError("bubblewrap unavailable; no host fallback")
    if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise RuntimeError("unprivileged controller required")
    pass_fds = tuple(fd for fd in (sync_fd, seccomp_fd) if fd is not None)
    command = namespace_command(bwrap, executable, sync_fd, seccomp_fd, extra_environment, cwd)
    process = subprocess.Popen(command, stdin=source,
                               stdout=subprocess.PIPE if result_fd is None else result_fd,
                               stderr=subprocess.PIPE if diagnostic_fd is None else diagnostic_fd,
                               env={}, close_fds=True, pass_fds=pass_fds,
                                start_new_session=True)
    result = _collect(process, timeout=timeout, cancel=cancel, on_chunk=on_chunk,
                      eof_complete=result_fd is None and diagnostic_fd is None)
    return dict(result, bootstrap_sha256=identity, command=command)


def _collect(process, *, timeout, cancel=None, on_chunk=None, eof_complete=True):
    """Collect an owned process group with the existing bounds and cleanup.

    Callers select and validate their explicit execution policy before Popen.
    This helper does not select a program or provide an execution fallback.
    """
    # Ownership begins immediately after Popen, before any setup that can fail.
    try:
        _OWNED[process.pid] = process
        streams = [stream for stream in (process.stdout, process.stderr) if stream is not None]
        pending = list(streams)
        collected = {stream: bytearray() for stream in streams}
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        timed_out = False

        def drain(deadline):
            while pending:
                if time.monotonic() >= deadline:
                    raise TimeoutError("fixture collection deadline")
                ready, _, _ = select.select(pending, [], [], 0.05)
                for stream in ready:
                    data = os.read(stream.fileno(), 4096)
                    if not data:
                        pending.remove(stream)
                    else:
                        collected[stream].extend(data)
                        if len(collected[stream]) > 4096:
                            raise RuntimeError("fixture output limit")
                        if on_chunk:
                            on_chunk("stdout" if stream is process.stdout else "stderr", data)

        if cancel:
            cancel(process)
        try:
            deadline = time.monotonic() + timeout
            drain(deadline)
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except (TimeoutError, subprocess.TimeoutExpired):
            timed_out = True
    finally:
        _finish(process)
    return {"status": process.returncode, "timed_out": timed_out,
            "eof": eof_complete,
            "eof_streams": [name for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
                            if stream is not None],
            "stdout": bytes(collected.get(process.stdout, b"")),
            "stderr": bytes(collected.get(process.stderr, b""))}

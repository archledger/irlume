#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Static launcher tests in an empty root; no actual Python actor is executed."""

import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "launcher_build_owner", HERE / "measurement-job.py"
)
job = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(job)
SPEC = importlib.util.spec_from_file_location(
    "launcher_elf", HERE / "measurement-job-elf.py"
)
elf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(elf)

PROBE = r"""
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::process::Command;
unsafe extern "C" { fn getppid() -> i32; fn getpgrp() -> i32; fn dup2(old: i32, new: i32) -> i32; fn prctl(option: i32, ...) -> i32; }
#[repr(C)] struct Filter { code: u16, jt: u8, jf: u8, k: u32 }
#[repr(C)] struct Program { len: u16, filter: *const Filter }
fn hex(data: &[u8]) -> String { data.iter().map(|byte| format!("{byte:02x}")).collect() }
fn ids(label: &str) {
    // SAFETY: Pure process identity syscalls have no pointer arguments.
    println!("{label}={},{},{}", std::process::id(), unsafe {getppid()}, unsafe {getpgrp()});
}
fn standard(label: &str) {
    for fd in 0..=2 {
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        println!("{label}_stdio_{fd}={}", hex(target.as_os_str().as_bytes()));
    }
}
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().and_then(|a| a.to_str()) == Some("--feed") {
        let file = File::open("/dev/null").unwrap();
        // SAFETY: The fixture exclusively owns this new descriptor and FD9.
        assert_eq!(unsafe { dup2(file.as_raw_fd(), 9) }, 9);
        // SAFETY: The fixture creates a sparse descriptor well above its stdio.
        assert_eq!(unsafe { dup2(file.as_raw_fd(), 511) }, 511);
        drop(file);
        // SAFETY: No owned File remains for descriptor3. This raw duplicate is
        // deliberately inherited by the launcher to exercise the lower bound.
        assert_eq!(unsafe { dup2(9, 3) }, 3);
        ids("before");
        standard("before");
        for fd in [3,9,511] { println!("before_fd{fd}={}",std::fs::read_link(format!("/proc/self/fd/{fd}")).is_ok()); }
        std::io::stdout().flush().unwrap();
        let mut offset = 1;
        if args.get(1).and_then(|a| a.to_str()) == Some("--deny-close") {
            let errno: u32 = args[2].to_str().unwrap().parse().unwrap();
            assert!(errno == 1 || errno == 38);
            let filters = [Filter{code:0x20,jt:0,jf:0,k:0}, Filter{code:0x15,jt:0,jf:1,k:436},
                           Filter{code:0x06,jt:0,jf:0,k:0x00050000|errno}, Filter{code:0x06,jt:0,jf:0,k:0x7fff0000}];
            let program = Program{len:4,filter:filters.as_ptr()};
            // SAFETY: Kernel copies the live repr(C) filter array; fixed x86-64
            // fixture denies only close_range in this process and its exec.
            assert_eq!(unsafe { prctl(38,1_usize,0_usize,0_usize,0_usize) },0);
            assert_eq!(unsafe { prctl(22,2_usize,&program as *const Program,0_usize,0_usize) },0);
            offset = 3;
        }
        let mut command = Command::new("/launcher");
        if args.get(offset).and_then(|arg| arg.to_str()) == Some("--raw-invalid") {
            command.arg(std::ffi::OsString::from_vec(vec![0xff]));
        } else {
            command.args(&args[offset..]);
        }
        let _error = command.exec();
        std::process::exit(91);
    }
    ids("after");
    standard("after");
    for fd in [3,9,511] { println!("after_fd{fd}={}",std::fs::read_link(format!("/proc/self/fd/{fd}")).is_ok()); }
    for arg in std::env::args_os() { println!("arg={}",hex(arg.as_bytes())); }
    let mut env: Vec<_> = std::env::vars_os().collect();
    env.sort();
    for (key,value) in env { println!("env={}:{}",hex(key.as_bytes()),hex(value.as_bytes())); }
}
"""


class LauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
            raise RuntimeError("static launcher tests require Linux x86-64")
        build = os.environ.get("IRLUME_LAUNCHER_BUILD_DIR")
        if build:
            cls.work = Path(build)
            cls.work.mkdir(mode=0o700)
        else:
            cls.work = Path(
                tempfile.mkdtemp(
                    prefix="irlume-launcher-", dir=os.environ.get("TMPDIR")
                )
            )
            cls.addClassCleanup(shutil.rmtree, cls.work)
        requested = os.environ.get("IRLUME_LAUNCHER_EVIDENCE")
        if requested:
            cls.evidence = Path(requested)
            cls.evidence.mkdir(mode=0o700)
        else:
            cls.evidence = Path(
                tempfile.mkdtemp(
                    prefix="irlume-launcher-evidence-", dir=os.environ.get("TMPDIR")
                )
            )
            print("Launcher evidence retained at", cls.evidence)
        cls.counter = 0
        cls.environment = {
            "HOME": str(Path.home()),
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "TMPDIR": str(cls.work),
        }
        cls.rustup, cls.bwrap = shutil.which("rustup"), shutil.which("bwrap")
        if cls.rustup is None or cls.bwrap is None:
            raise RuntimeError(
                "pinned Rust and bubblewrap are required; no host fallback"
            )
        cls.launcher, cls.probe = cls.work / "launcher", cls.work / "probe"
        launcher_source = cls.work / "launcher.rs"
        launcher_source.write_bytes((HERE / "measurement-job-launcher.rs").read_bytes())
        launcher_source.chmod(0o400)
        probe_source = cls.work / "probe.rs"
        probe_source.write_text(PROBE)
        probe_source.chmod(0o400)
        cls.binary_facts = {}
        for name, source, output in (
            ("launcher", launcher_source, cls.launcher),
            ("probe", probe_source, cls.probe),
        ):
            command = [
                cls.rustup,
                "run",
                "1.88.0",
                "rustc",
                "--edition=2021",
                "--crate-name",
                "fixture_" + name,
                "--target",
                "x86_64-unknown-linux-musl",
                "-Ctarget-feature=+crt-static",
                "-Crelocation-model=static",
                "-Clink-arg=-no-pie",
                "-Cpanic=abort",
                "-Copt-level=s",
                "-Ccodegen-units=1",
                "-Dwarnings",
                source.name,
                "-o",
                str(output),
            ]
            source_facts = cls.file_facts(source)
            result = cls.run_command("build-" + name, command, seconds=120)
            if result.returncode:
                raise RuntimeError(result.stderr)
            cls.check_file(source, source_facts)
            output.chmod(0o500)
            data = output.read_bytes()
            metadata = elf.inspect(data)
            if (
                metadata["type"] != 2
                or metadata["dynamic"]
                or metadata["interpreter"] is not None
            ):
                raise RuntimeError("test executable is not static ET_EXEC")
            cls.binary_facts[output] = cls.file_facts(output)
            (cls.evidence / (name + "-elf.json")).write_text(
                json.dumps(
                    {
                        "metadata": metadata,
                        "source_sha256": source_facts["sha256"],
                        "source_identity": source_facts["identity"],
                        "binary_sha256": hashlib.sha256(data).hexdigest(),
                        "binary_identity": cls.binary_facts[output]["identity"],
                    },
                    indent=2,
                )
                + "\n"
            )

    @staticmethod
    def file_facts(path):
        before = path.lstat()
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        identity = tuple(getattr(before, key) for key in fields)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & 0o222
            or before.st_nlink != 1
        ):
            raise RuntimeError("mutable or aliased test artifact")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if tuple(getattr(path.lstat(), key) for key in fields) != identity:
            raise RuntimeError("test artifact changed during observation")
        return {"identity": identity, "sha256": digest}

    @classmethod
    def check_file(cls, path, expected):
        if cls.file_facts(path) != expected:
            raise RuntimeError("test artifact no longer matches selected bytes")

    @classmethod
    def run_command(cls, label, command, *, seconds=15):
        cls.counter += 1
        label = f"{cls.counter:02}-" + label

        def emit(_, record, stdout, stderr):
            (cls.evidence / (label + ".json")).write_text(
                json.dumps(record, indent=2) + "\n"
            )
            (cls.evidence / (label + ".log")).write_bytes(
                stdout + b"\nSTDERR\n" + stderr
            )

        return job.CompilerCommand(
            label, time.monotonic() + seconds, emit, limit=1024 * 1024
        ).run(command, cls.environment, cwd=str(cls.work))

    def execute(self, arguments, *, interpreter="probe", denial=None):
        for path, expected in self.binary_facts.items():
            self.check_file(path, expected)
        command = [
            self.bwrap,
            "--die-with-parent",
            "--unshare-user",
            "--uid",
            str(os.getuid()),
            "--gid",
            str(os.getgid()),
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--clearenv",
            "--dir",
            "/usr/bin",
            "--dir",
            "/bin",
            "--dir",
            "/opt/irlume",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            str(self.launcher),
            "/launcher",
            "--ro-bind",
            str(self.probe),
            "/feeder",
            "--ro-bind",
            str(self.probe),
            "/bin/sh",
            "--info-fd",
            "3",
        ]
        if interpreter != "missing":
            target = self.probe
            if interpreter in ("invalid", "non-executable"):
                target = self.work / (interpreter + ".txt")
                target.write_text("not an executable image\n")
                target.chmod(0o500 if interpreter == "invalid" else 0o400)
            command += ["--ro-bind", str(target), "/usr/bin/python3"]
        poison = {
            "LD_PRELOAD": "/untrusted.so",
            "LD_AUDIT": "/audit.so",
            "LD_LIBRARY_PATH": "/untrusted",
            "GLIBC_TUNABLES": "untrusted.marker=1",
            "PYTHONPATH": "/untrusted",
            "IRLUME_POISON": "must-not-survive",
        }
        for key, value in poison.items():
            command += ["--setenv", key, value]
        command += ["/feeder", "--feed"]
        if denial is not None:
            command += ["--deny-close", str(denial)]
        command += arguments
        info_path = self.work / f"bwrap-info-{self.counter + 1}.json"
        wrapper = """import os,sys
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
if fd != 3:
    os.dup2(fd,3,inheritable=True)
    os.close(fd)
else:
    os.set_inheritable(fd,True)
os.execv(sys.argv[2],sys.argv[2:])
"""
        result = self.run_command(
            "inert-exec",
            ["/usr/bin/python3", "-I", "-S", "-c", wrapper, str(info_path), *command],
        )
        for path, expected in self.binary_facts.items():
            self.check_file(path, expected)
        info = info_path.read_bytes()
        self.assertLessEqual(len(info), 65536)
        (self.evidence / info_path.name).write_bytes(info)
        result.child_info = json.loads(info) if info else None
        return result

    def test_changed_test_artifact_is_rejected(self):
        path = self.work / "artifact-control"
        path.write_bytes(b"one")
        path.chmod(0o400)
        expected = self.file_facts(path)
        path.chmod(0o600)
        path.write_bytes(b"two")
        path.chmod(0o400)
        with self.assertRaises(RuntimeError):
            self.check_file(path, expected)

    def test_static_launcher_clears_environment_preserves_identity_and_closes_fd(self):
        result = self.execute(["--host"])
        self.assertEqual(result.returncode, 0, result.stderr)
        before = re.search(r"^before=(\d+,\d+,\d+)$", result.stdout, re.MULTILINE)
        after = re.search(r"^after=(\d+,\d+,\d+)$", result.stdout, re.MULTILINE)
        self.assertIsNotNone(before, result.stdout)
        self.assertIsNotNone(after, result.stdout)
        self.assertEqual(before.group(1), after.group(1))
        self.assertIsNotNone(result.child_info, result.stderr)
        self.assertEqual(
            result.child_info["child-pid"], int(after.group(1).split(",")[0])
        )
        for fd in (3, 9, 511):
            self.assertIn(f"before_fd{fd}=true", result.stdout)
            self.assertIn(f"after_fd{fd}=false", result.stdout)
        for fd in range(3):
            before_fd = re.search(
                rf"^before_stdio_{fd}=([0-9a-f]+)$", result.stdout, re.MULTILINE
            )
            after_fd = re.search(
                rf"^after_stdio_{fd}=([0-9a-f]+)$", result.stdout, re.MULTILINE
            )
            self.assertIsNotNone(before_fd, result.stdout)
            self.assertIsNotNone(after_fd, result.stdout)
            self.assertEqual(before_fd.group(1), after_fd.group(1))
        environment = {
            bytes.fromhex(key).decode(): bytes.fromhex(value).decode()
            for key, value in re.findall(
                r"^env=([0-9a-f]+):([0-9a-f]*)$", result.stdout, re.MULTILINE
            )
        }
        self.assertEqual(environment, {"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
        args = [
            bytes.fromhex(value).decode()
            for value in re.findall(r"^arg=([0-9a-f]+)$", result.stdout, re.MULTILINE)
        ]
        self.assertEqual(
            args,
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                "-X",
                "pycache_prefix=/dev/null",
                "/opt/irlume/measurement-job-guardian-host.py",
            ],
        )

    def test_exec_failures_refuse_without_shell_or_observation_execution(self):
        for target in ("missing", "non-executable", "invalid"):
            with self.subTest(target=target):
                result = self.execute(["--host"], interpreter=target)
                self.assertIn("before_fd9=true", result.stdout)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertNotIn("after=", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_denied_or_unsupported_descriptor_sweep_refuses_before_exec(self):
        for errno in (1, 38):
            with self.subTest(errno=errno):
                result = self.execute(["--host"], denial=errno)
                self.assertIn("before_fd9=true", result.stdout)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertNotIn("after=", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_bad_arguments_refuse_without_loading_actor(self):
        for args in (
            ["--host", "extra"],
            ["--unknown"],
            ["--raw-invalid"],
            ["--host", *["extra"] * 64],
            ["--guardian", "/a/guardian-config.json", "a" * 64, "extra"],
        ):
            with self.subTest(args=args):
                result = self.execute(args)
                self.assertIn("before_fd9=true", result.stdout)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertNotIn("after=", result.stdout)

    def test_guest_and_guardian_forward_only_the_selected_arguments(self):
        digest = "c" * 64
        for request, expected in (
            (["--guest"], ["/opt/irlume/measurement-job-boot.py"]),
            (
                ["--guardian", "/private/guardian-config.json", digest],
                [
                    "/opt/irlume/measurement-job-guardian-native.py",
                    "--service",
                    "/private/guardian-config.json",
                    digest,
                ],
            ),
        ):
            with self.subTest(request=request):
                result = self.execute(request)
                self.assertEqual(result.returncode, 0, result.stderr)
                args = [
                    bytes.fromhex(value).decode()
                    for value in re.findall(
                        r"^arg=([0-9a-f]+)$", result.stdout, re.MULTILINE
                    )
                ]
                self.assertEqual(args[6:], expected)
                self.assertIn("after_fd9=false", result.stdout)


if __name__ == "__main__":
    unittest.main()

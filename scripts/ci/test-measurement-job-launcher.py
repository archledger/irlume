#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Static launcher tests in an empty root; no actual Python actor is executed."""

import ctypes
import errno
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
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::Command;
unsafe extern "C" { fn getppid() -> i32; fn getpgrp() -> i32; fn dup2(old: i32, new: i32) -> i32; fn prctl(option: i32, ...) -> i32;
                    fn fork() -> i32; fn pipe(fds: *mut i32) -> i32; fn fcntl(fd: i32, command: i32, ...) -> i32;
                    fn kill(pid: i32, signal: i32) -> i32; }
#[repr(C)] struct Filter { code: u16, jt: u8, jf: u8, k: u32 }
#[repr(C)] struct Program { len: u16, filter: *const Filter }
fn hex(data: &[u8]) -> String { data.iter().map(|byte| format!("{byte:02x}")).collect() }
fn open_descriptors() -> String {
    // SAFETY: F_GETFD (1) only reads the descriptor flags of each number.
    (3..4096).filter(|&fd| unsafe { fcntl(fd, 1) } >= 0).map(|fd| fd.to_string()).collect::<Vec<_>>().join(",")
}
fn errno<T>(result: std::io::Result<T>) -> i32 { result.map_or_else(|error| error.raw_os_error().unwrap_or(-1), |_| 0) }
fn signal_helper() -> i32 {
    let Some(pid) = std::fs::read_to_string("/private/helper.pid").ok().and_then(|text| text.parse().ok()) else { return -1 };
    // SAFETY: Signal 0 sends nothing; the kernel only checks the permission.
    if unsafe { kill(pid, 0) } == 0 { 0 } else { errno::<()>(Err(std::io::Error::last_os_error())) }
}
fn abstract_name() -> SocketAddr { SocketAddr::from_abstract_name(b"irlume-launcher-abstract").unwrap() }
fn mode(path: &str, bits: u32) { std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap(); }
fn listen(variant: &str) {
    // Listeners live in a helper created before the launcher runs, so they are
    // outside any Landlock domain and survive the launcher's close_range.
    let mut fds = [0_i32; 2];
    // SAFETY: The kernel writes two descriptors into the live array.
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
    let parent = std::process::id() as i32;
    // SAFETY: The feeder is single-threaded; the helper only binds and sleeps.
    let pid = unsafe { fork() };
    assert!(pid >= 0);
    // SAFETY: Each pipe end is owned exactly once in each process.
    let (read, write) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    if pid > 0 {
        drop(write);
        let mut byte = [0_u8; 1];
        (&read).read_exact(&mut byte).unwrap();
        return;
    }
    drop(read);
    // SAFETY: PR_SET_PDEATHSIG (1) with SIGKILL takes no pointer.
    assert_eq!(unsafe { prctl(1, 9_usize, 0_usize, 0_usize, 0_usize) }, 0);
    // SAFETY: getppid has no arguments; a changed parent means the feeder died.
    if unsafe { getppid() } != parent { std::process::exit(92); }
    let _other = UnixListener::bind("/private/other.sock").unwrap();
    let _datagram = UnixDatagram::bind("/private/datagram.sock").unwrap();
    let _abstract = UnixListener::bind_addr(&abstract_name()).unwrap();
    // The sandbox has its own network namespace, so the fixed port is free.
    let _tcp = TcpListener::bind("127.0.0.1:4000").unwrap();
    std::fs::write("/private/helper.pid", std::process::id().to_string()).unwrap();
    let _control = match variant {
        "socket" | "mode" => {
            let control = UnixListener::bind("/private/control.sock").unwrap();
            mode("/private/control.sock", if variant == "socket" { 0o600 } else { 0o644 });
            Some(control)
        }
        "symlink" => {
            let target = UnixListener::bind("/private/target.sock").unwrap();
            mode("/private/target.sock", 0o600);
            std::os::unix::fs::symlink("target.sock", "/private/control.sock").unwrap();
            Some(target)
        }
        "regular" => { File::create("/private/control.sock").unwrap(); mode("/private/control.sock", 0o600); None }
        "missing" => None,
        _ => std::process::exit(93),
    };
    let null = File::options().read(true).write(true).open("/dev/null").unwrap();
    // SAFETY: The helper replaces only its own stdio with /dev/null.
    for fd in 0..=2 { assert_eq!(unsafe { dup2(null.as_raw_fd(), fd) }, fd); }
    (&write).write_all(b"1").unwrap();
    drop(write);
    loop { std::thread::sleep(std::time::Duration::from_secs(60)); }
}
fn seccomp(filters: &[Filter]) {
    let program = Program{len:filters.len() as u16,filter:filters.as_ptr()};
    // SAFETY: Kernel copies the live repr(C) filter array; the fixed x86-64
    // fixture filters only this process and its exec.
    assert_eq!(unsafe { prctl(38,1_usize,0_usize,0_usize,0_usize) },0);
    assert_eq!(unsafe { prctl(22,2_usize,&program as *const Program,0_usize,0_usize) },0);
}
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
        println!("before_open={}", open_descriptors());
        std::io::stdout().flush().unwrap();
        let mut offset = 1;
        if args.get(offset).and_then(|a| a.to_str()) == Some("--listen") {
            listen(args[offset + 1].to_str().unwrap());
            offset += 2;
        }
        let number = |index: usize| -> u32 { args[index].to_str().unwrap().parse().unwrap() };
        if args.get(offset).and_then(|a| a.to_str()) == Some("--deny") {
            let (syscall, errno) = (number(offset + 1), number(offset + 2));
            assert!([436, 444, 445, 446].contains(&syscall) && [1, 22, 38].contains(&errno));
            seccomp(&[Filter{code:0x20,jt:0,jf:0,k:0}, Filter{code:0x15,jt:0,jf:1,k:syscall},
                      Filter{code:0x06,jt:0,jf:0,k:0x00050000|errno}, Filter{code:0x06,jt:0,jf:0,k:0x7fff0000}]);
            offset += 3;
        } else if args.get(offset).and_then(|a| a.to_str()) == Some("--restrict-flags") {
            // EPERM from landlock_restrict_self (446) unless args[1] is exactly this value.
            let flags = number(offset + 1);
            seccomp(&[Filter{code:0x20,jt:0,jf:0,k:0}, Filter{code:0x15,jt:0,jf:5,k:446},
                      Filter{code:0x20,jt:0,jf:0,k:24}, Filter{code:0x15,jt:0,jf:2,k:flags},
                      Filter{code:0x20,jt:0,jf:0,k:28}, Filter{code:0x15,jt:1,jf:0,k:0},
                      Filter{code:0x06,jt:0,jf:0,k:0x00050001}, Filter{code:0x06,jt:0,jf:0,k:0x7fff0000}]);
            offset += 2;
        } else if args.get(offset).and_then(|a| a.to_str()) == Some("--deny-version") {
            // The errno only for landlock_create_ruleset (444) with args[2] exactly
            // LANDLOCK_CREATE_RULESET_VERSION (1); the ruleset call itself passes.
            let errno = number(offset + 1);
            assert!([38, 95].contains(&errno));
            seccomp(&[Filter{code:0x20,jt:0,jf:0,k:0}, Filter{code:0x15,jt:0,jf:5,k:444},
                      Filter{code:0x20,jt:0,jf:0,k:32}, Filter{code:0x15,jt:0,jf:3,k:1},
                      Filter{code:0x20,jt:0,jf:0,k:36}, Filter{code:0x15,jt:0,jf:1,k:0},
                      Filter{code:0x06,jt:0,jf:0,k:0x00050000|errno}, Filter{code:0x06,jt:0,jf:0,k:0x7fff0000}]);
            offset += 2;
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
    if args.first().and_then(|a| a.to_str()) == Some("--child-connect") {
        std::process::exit(errno(UnixStream::connect(&args[1])));
    }
    ids("after");
    standard("after");
    for fd in [3,9,511] { println!("after_fd{fd}={}",std::fs::read_link(format!("/proc/self/fd/{fd}")).is_ok()); }
    println!("after_open={}", open_descriptors());
    println!("probe_control={}", errno(UnixStream::connect("/private/control.sock")));
    println!("probe_other={}", errno(UnixStream::connect("/private/other.sock")));
    println!("probe_abstract={}", errno(UnixStream::connect_addr(&abstract_name())));
    println!("probe_datagram={}", errno(UnixDatagram::unbound().and_then(|s| s.send_to(b"x", "/private/datagram.sock"))));
    println!("probe_bind={}", errno(UnixListener::bind("/private/new.sock")));
    println!("probe_pair={}", errno(UnixStream::pair()));
    let child = Command::new("/usr/bin/python3").args(["--child-connect", "/private/other.sock"]).status().unwrap();
    println!("probe_child_other={}", child.code().unwrap_or(-1));
    println!("probe_tcp_bind={}", errno(TcpListener::bind("127.0.0.1:0")));
    println!("probe_tcp_connect={}", errno(TcpStream::connect("127.0.0.1:4000")));
    println!("probe_udp_send={}", errno(UdpSocket::bind("127.0.0.1:0").and_then(|s| s.send_to(b"x", "127.0.0.1:4000"))));
    println!("probe_signal_helper={}", signal_helper());
    for arg in std::env::args_os() { println!("arg={}",hex(arg.as_bytes())); }
    let mut env: Vec<_> = std::env::vars_os().collect();
    env.sort();
    for (key,value) in env { println!("env={}:{}",hex(key.as_bytes()),hex(value.as_bytes())); }
}
"""
GUARDIAN = ["--guardian", "/private/guardian-config.json", "c" * 64]
# Expected errno per probe inside the guardian's Landlock domain. Listeners are
# live, so EACCES is Landlock's (net/unix/af_unix.c:1223-1236 run first). The
# domain handles no network access and no signal scope, so TCP, UDP and signals
# to the helper outside the domain pass (landlock.h:465-468, 493).
CONFINED = {
    "control": 0,
    "other": errno.EACCES,
    "abstract": errno.EPERM,
    "datagram": errno.EACCES,
    "bind": errno.EACCES,
    "pair": 0,
    "child_other": errno.EACCES,
    "tcp_bind": 0,
    "tcp_connect": 0,
    "udp_send": 0,
    "signal_helper": 0,
}


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
        # x86-64 landlock_create_ruleset (444) with NULL, 0 and the version flag
        # returns the ABI (security/landlock/syscalls.c:223-228); RESOLVE_UNIX
        # needs 9 (landlock.h:329).
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        version = ctypes.c_uint(1)
        if libc.syscall(ctypes.c_long(444), None, ctypes.c_size_t(0), version) < 9:
            raise RuntimeError("Landlock ABI 9 or later is required; no host fallback")
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

    def execute(
        self,
        arguments,
        *,
        interpreter="probe",
        denial=None,
        listen=None,
        restrict_flags=None,
        version_denial=None,
    ):
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
        if listen is not None:
            command += ["--tmpfs", "/private"]
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
        if listen is not None:
            command += ["--listen", listen]
        if denial is not None:
            command += ["--deny", *map(str, denial)]
        if restrict_flags is not None:
            command += ["--restrict-flags", str(restrict_flags)]
        if version_denial is not None:
            command += ["--deny-version", str(version_denial)]
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
        for code in (errno.EPERM, errno.ENOSYS):
            with self.subTest(errno=code):
                result = self.execute(["--host"], denial=(436, code))
                self.assertIn("before_fd9=true", result.stdout)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertNotIn("after=", result.stdout)
                self.assertEqual(result.stderr, "")

    def probes(self, result):
        return {
            key: int(value)
            for key, value in re.findall(
                r"^probe_([a-z_]+)=(-?\d+)$", result.stdout, re.MULTILINE
            )
        }

    def assert_started(self, result, probes):
        self.assertEqual(result.returncode, 0, result.stderr)
        before = re.search(r"^before_open=([0-9,]*)$", result.stdout, re.MULTILINE)
        self.assertIsNotNone(before, result.stdout)
        self.assertLessEqual({"3", "9", "511"}, set(before.group(1).split(",")))
        # The ruleset and O_PATH descriptors must not reach the new image.
        self.assertRegex(result.stdout, r"(?m)^after_open=$")
        self.assertEqual(self.probes(result), probes)

    def assert_refused(self, result):
        self.assertIn("before_fd9=true", result.stdout)
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertNotIn("after=", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_guardian_resolves_only_the_bound_control_socket(self):
        result = self.execute(GUARDIAN, listen="socket")
        self.assert_started(result, CONFINED)

    def test_guardian_passes_exactly_log_new_exec_on_to_restrict_self(self):
        # LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON (landlock.h:197); any other
        # flags value makes the filter return EPERM and the launcher refuse.
        result = self.execute(GUARDIAN, listen="socket", restrict_flags=2)
        self.assert_started(result, CONFINED)

    def test_host_role_is_not_confined_and_does_not_query_landlock(self):
        for denial in (None, (444, errno.ENOSYS)):
            with self.subTest(denial=denial):
                result = self.execute(["--host"], listen="socket", denial=denial)
                self.assert_started(result, dict.fromkeys(CONFINED, 0))

    def test_guardian_refuses_without_a_private_control_socket_node(self):
        for variant in ("missing", "regular", "mode", "symlink"):
            with self.subTest(variant=variant):
                self.assert_refused(self.execute(GUARDIAN, listen=variant))

    def test_denied_or_unsupported_landlock_refuses_before_exec(self):
        # 444-446 are landlock_create_ruleset/add_rule/restrict_self
        # (arch/x86/entry/syscalls/syscall_64.tbl:371-373).
        for number in (444, 445, 446):
            for code in (errno.ENOSYS, errno.EPERM, errno.EINVAL):
                with self.subTest(syscall=number, errno=code):
                    result = self.execute(
                        GUARDIAN, listen="socket", denial=(number, code)
                    )
                    self.assert_refused(result)

    def test_guardian_refuses_when_only_the_abi_query_fails(self):
        # As without Landlock (syscalls.c:220-221); the ruleset call would pass.
        for code in (errno.ENOSYS, errno.EOPNOTSUPP):
            with self.subTest(errno=code):
                result = self.execute(GUARDIAN, listen="socket", version_denial=code)
                self.assert_refused(result)

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
        for request, expected, listen in (
            (["--guest"], ["/opt/irlume/measurement-job-boot.py"], None),
            (
                GUARDIAN,
                [
                    "/opt/irlume/measurement-job-guardian-native.py",
                    "--service",
                    "/private/guardian-config.json",
                    GUARDIAN[2],
                ],
                "socket",
            ),
        ):
            with self.subTest(request=request):
                result = self.execute(request, listen=listen)
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

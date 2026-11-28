import os
from pathlib import Path
import re
import subprocess
import sys

from native.sdk_manifest import verify_sdk

BWRAP = "/usr/bin/bwrap"
LIBRARIES = ("libcamera.so.0.8", "libcamera-base.so.0.8")
WITNESS = "libcamera link witness: 0.8.0\n"

PREFLIGHT = r"""
import os
from pathlib import Path

for pattern in ('video*', 'media*', 'v4l-subdev*', 'tpm*'):
    assert not list(Path('/dev').glob(pattern)), pattern
assert not list(Path('/run').iterdir())
assert not list(Path('/home').iterdir())
assert not list(Path('/sys').iterdir())
assert not list(Path('/etc').iterdir())
assert Path.cwd() == Path('/tmp')
assert all(name not in os.environ for name in
           ('DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'DBUS_SESSION_BUS_ADDRESS'))
print(os.readlink('/proc/self/ns/user'))
print(os.readlink('/proc/self/ns/net'))
"""


def sandbox_run(argv, *, mounts=(), env=(), timeout=15) -> subprocess.CompletedProcess:
    for path in ("/lib", "/lib64"):
        if Path(path).resolve(strict=True) != Path("/usr/lib"):
            raise ValueError(f"unexpected Arch loader path: {path}")
    args = [
        BWRAP, "--unshare-all", "--new-session", "--die-with-parent", "--clearenv",
        "--cap-drop", "ALL",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
        "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
        "--dir", "/etc", "--dir", "/run", "--dir", "/home", "--dir", "/sys",
        "--dir", "/sdk", "--dir", "/sdk/lib",
        "--dir", "/tmp/fixture-home", "--chdir", "/tmp",
        "--setenv", "HOME", "/tmp/fixture-home", "--setenv", "PATH", "/usr/bin",
        "--setenv", "LC_ALL", "C",
    ]
    for source, dest in mounts:
        args.extend(("--ro-bind", str(source), dest))
    for name, value in env:
        args.extend(("--setenv", name, value))
    args.extend(("--", *argv))
    return subprocess.run(
        args, check=True, text=True, capture_output=True, stdin=subprocess.DEVNULL,
        close_fds=True, timeout=timeout, env={"PATH": "/usr/bin", "LC_ALL": "C"},
    )


def verify_loader(trace: str) -> None:
    initialized = [
        path for path in re.findall(r"calling init:\s+([^\s]+)", trace)
        if Path(path).name.startswith(("libcamera.so", "libcamera-base.so"))
    ]
    if sorted(initialized) != sorted(f"/sdk/lib/{name}" for name in LIBRARIES):
        raise ValueError("unexpected SDK loader resolution")


def fixture_count(output: str) -> int:
    start = re.findall(r"^running (\d+) tests?$", output, re.M)
    end = re.findall(
        r"^test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; "
        r"0 filtered out; finished in [\d.]+s$",
        output, re.M,
    )
    if len(start) != 1 or start != end or int(start[0]) == 0:
        raise ValueError("expected a nonzero full fixture count with no skips")
    return int(start[0])


def _scratch_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("inputs must use canonical absolute paths")
    if not path.is_relative_to("/tmp/opencode") or path == Path("/tmp/opencode"):
        raise ValueError("inputs must be in private /tmp/opencode scratch")
    return path


def run_proof(sdk: Path, manifest: Path, witness: Path, fixture: Path) -> int:
    if os.geteuid() == 0:
        raise ValueError("run this proof without privilege")
    libraries = verify_sdk(sdk, manifest)
    mounts = (
        *((source, f"/sdk/lib/{name}") for source, name in zip(libraries, LIBRARIES, strict=True)),
        (witness, "/libcamera-link"),
    )
    outer = [os.readlink("/proc/self/ns/user"), os.readlink("/proc/self/ns/net")]
    preflight = sandbox_run(("/usr/bin/python3", "-I", "-c", PREFLIGHT))
    inner = preflight.stdout.splitlines()
    if (len(inner) != 2 or not inner[0].startswith("user:[") or not inner[1].startswith("net:[")
            or any(a == b for a, b in zip(inner, outer, strict=True))):
        raise ValueError("user and network namespace isolation not confirmed")
    linked = sandbox_run(
        ("/libcamera-link",), mounts=mounts,
        env=(("LD_BIND_NOW", "1"), ("LD_LIBRARY_PATH", "/sdk/lib"), ("LD_DEBUG", "libs")),
    )
    verify_loader(linked.stderr)
    if linked.stdout != WITNESS:
        raise ValueError("unexpected link witness output")
    tests = sandbox_run(("/fixture-test",), mounts=((fixture, "/fixture-test"),))
    count = fixture_count(tests.stdout)
    print(linked.stdout, end="")
    print("SDK loader resolution confirmed for libcamera and libcamera-base.")
    print(tests.stdout, end="")
    print("No-device proof passed (link and synthetic fixtures only).")
    return count


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: run_isolated.py SDK SDK_MANIFEST LINK_WITNESS FIXTURE_TEST_BIN", file=sys.stderr)
        return 2
    try:
        run_proof(*map(_scratch_path, argv))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"No-device proof refused: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print("\n".join(error.stderr.splitlines()[-12:]), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

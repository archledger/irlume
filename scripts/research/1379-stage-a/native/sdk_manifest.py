import hashlib
from pathlib import Path, PurePosixPath
import re
import sys


def _inside(root: Path, path: Path) -> Path:
    actual = path.resolve(strict=True)
    if not actual.is_relative_to(root):
        raise ValueError(f"outside SDK: {path}")
    return actual


def verify_sdk(sdk: Path, manifest: Path) -> tuple[Path, Path]:
    root = sdk.resolve(strict=True)
    files = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        record = re.fullmatch(r"([0-9a-f]{64})  ([a-zA-Z0-9_.+/-]+)", line)
        if record is None:
            raise ValueError("invalid SDK receipt line")
        expected, relative = record.groups()
        parts = PurePosixPath(relative)
        if parts.is_absolute() or ".." in parts.parts or parts.as_posix() != relative:
            raise ValueError(f"invalid SDK receipt path: {relative}")
        path = root / relative
        if _inside(root, path) != path or path in files or not path.is_file():
            raise ValueError(f"invalid or duplicate SDK receipt file: {relative}")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                raise ValueError(f"checksum mismatch: {relative}")
        files.add(path)

    for header in (root / "include").rglob("*.h"):
        if header not in files:
            raise ValueError(f"unlisted SDK header: {header}")
    libraries = (
        _inside(root, root / "lib/libcamera.so"),
        _inside(root, root / "lib/libcamera-base.so"),
    )
    required = {
        *libraries,
        root / "lib/pkgconfig/libcamera.pc",
        root / "lib/pkgconfig/libcamera-base.pc",
        root / "lib/libcamera/ipa/ipa_ipu3.so",
        root / "include/libcamera/libcamera/camera.h",
    }
    if not required <= files:
        raise ValueError("SDK receipt missing required inputs")
    return libraries


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: sdk_manifest.py SDK SDK_MANIFEST")
    try:
        print(*verify_sdk(Path(sys.argv[1]), Path(sys.argv[2])), sep="\n")
    except (OSError, ValueError) as error:
        sys.exit(str(error))

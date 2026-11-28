from pathlib import Path
import re
import sys


def check_headers(mode: str, root: Path, trace: str) -> None:
    if mode == "uapi":
        namespaces = {"linux", "asm", "asm-generic"}
        mandatory = {"linux/media.h", "linux/videodev2.h"}
    elif mode == "libcamera":
        namespaces = {"libcamera"}
        mandatory = {
            f"libcamera/{name}.h" for name in
            ("camera", "camera_manager", "framebuffer", "framebuffer_allocator", "request", "stream")
        }
    else:
        raise ValueError("unexpected header witness mode")

    root = root.resolve(strict=True)
    seen = set()
    for name in re.findall(r"^\.+ (.+)$", trace, re.M):
        path = Path(name)
        if not namespaces.intersection(path.parts):
            continue
        path = path.resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError(f"{mode} header outside verified include root: {path}")
        seen.add(path.relative_to(root).as_posix())
    if not mandatory <= seen:
        raise ValueError(f"missing {mode} header witness: {', '.join(sorted(mandatory - seen))}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: check_headers.py MODE INCLUDE_ROOT GCC_HEADER_TRACE")
    try:
        check_headers(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]).read_text())
    except (OSError, ValueError) as error:
        sys.exit(str(error))

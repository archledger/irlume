import hashlib
import os
from pathlib import Path


def executable_receipt(path: Path) -> str:
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"not an executable file: {path}")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return f"{digest}  {path.name}\n"


def verify_executable(path: Path) -> None:
    receipt = path.with_name(path.name + ".sha256")
    if receipt.is_symlink() or not receipt.is_file():
        raise ValueError(f"missing executable build receipt: {path.name}")
    if receipt.read_text(encoding="utf-8") != executable_receipt(path):
        raise ValueError(f"executable build receipt mismatch: {path.name}")

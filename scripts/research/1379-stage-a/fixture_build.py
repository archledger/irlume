import json
import os
from pathlib import Path
import subprocess
import sys

from artifact_receipt import executable_receipt
from run_isolated import _scratch_path


def build_fixture(target: Path) -> Path:
    source = Path(__file__).resolve().parent / "fixture" / "Cargo.toml"
    build = subprocess.run(
        (
            "cargo", "+1.88.0", "test", "--locked", "--offline", "--no-run",
            "--message-format=json", "--manifest-path", str(source),
        ),
        env={**os.environ, "CARGO_TARGET_DIR": str(target)},
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        check=True,
        text=True,
        timeout=60,
    )
    executable, = [
        item["executable"] for item in map(json.loads, build.stdout.splitlines())
        if item["reason"] == "compiler-artifact" and item["profile"]["test"]
        and item["target"]["name"] == "irlume_book2_stage_a" and item["executable"]
    ]
    path = _scratch_path(executable)
    if not path.is_relative_to(target):
        raise ValueError("fixture executable is outside the chosen Cargo target directory")
    path.with_name(path.name + ".sha256").write_text(executable_receipt(path), encoding="utf-8")
    return path


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: fixture_build.py PRIVATE_CARGO_TARGET_DIR")
    try:
        print(build_fixture(_scratch_path(sys.argv[1])))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Fixture build refused: {error}")

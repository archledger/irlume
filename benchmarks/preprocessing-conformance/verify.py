#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Run experiment checks serially and retain exact output/return-code receipts."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REL = str(HERE.relative_to(ROOT))


def check_commands():
    return [
        [sys.executable, f"{REL}/run.py"],
        [sys.executable, "-m", "unittest", "discover", "-s", REL, "-p", "test_*.py", "-v"],
        ["rustfmt", "+1.88.0", "--check", "--edition", "2021", f"{REL}/probe.rs"],
        ["rustup", "run", "1.88.0", "clippy-driver", "--edition=2021", "-Dwarnings",
         "-Ccodegen-units=1", f"{REL}/build/probe.rs", "-o", f"{REL}/build/probe-clippy"],
        ["git", "diff", "--check", "--", REL],
        [sys.executable, f"{REL}/run.py", "--check-sources"],
        ["git", "status", "--short", "--untracked-files=all", "--", REL],
        [sys.executable, f"{REL}/run.py"],
    ]


def write_receipts(receipts):
    temporary = HERE / "checks.json.tmp"
    temporary.write_text(json.dumps(receipts, indent=2) + "\n")
    temporary.replace(HERE / "checks.json")


def main():
    receipts = []
    repeat_identical = None
    commands = check_commands()
    # Invalidate an older success before starting any subprocess.
    write_receipts([{"status": "running"}])
    try:
        for argv in commands:
            try:
                result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, check=False)
            except OSError as error:
                receipts.append({"command": argv, "returncode": None,
                                 "stdout": "", "stderr": str(error)})
                raise
            receipts.append({"command": argv, "returncode": result.returncode,
                             "stdout": result.stdout, "stderr": result.stderr})
            write_receipts([*receipts, {"status": "running"}])
            if result.returncode != 0:
                raise RuntimeError(f"check failed: {argv}: {result.stderr}")
        repeat_identical = receipts[0]["stdout"] == receipts[-1]["stdout"]
        if not repeat_identical:
            raise AssertionError("identical-input experiment outputs differ between runs")
        results = (HERE / "results.json").read_bytes()
        if results.decode() != receipts[-1]["stdout"]:
            raise AssertionError("results file differs from experiment stdout")
    except Exception as error:
        receipts.append({"status": "failed", "error": str(error),
                         "repeat_stdout_identical": repeat_identical})
        write_receipts(receipts)
        raise
    receipts.append({"status": "passed", "repeat_stdout_identical": True,
                     "results_sha256": hashlib.sha256(results).hexdigest()})
    write_receipts(receipts)
    print(f"PASS: {len(commands)} serial commands; repeated experiment stdout identical")
    print("results.json SHA256", hashlib.sha256(results).hexdigest())
    print(receipts[1]["stderr"])


if __name__ == "__main__":
    main()

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Camera-free subprocess regression checks for a built request evaluator."""

import subprocess
import sys
from pathlib import Path

from host import strict_json
from request_contract import checked_report


def check(binary):
    for arguments in ([b"--evaluate", b"private-fixture-\xff"], [b"--unknown"]):
        result = subprocess.run(
            [str(binary), *arguments], capture_output=True, timeout=5, check=False
        )
        assert result.returncode == 2, "malformed argument did not exit categorically"
        assert result.stderr == b"", "malformed argument exposed a diagnostic"
        assert b"private-fixture" not in result.stdout, (
            "private argument reached output"
        )
        report = checked_report(strict_json(result.stdout))
        assert report["result"] == {"kind": "refused", "cause": "invalid_request"}
        assert report["counts"] == dict.fromkeys(report["counts"], 0)
    print("2 malformed-argument subprocess cases passed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: check_binary.py /absolute/path/to/ir_request_evaluation"
        )
    check(Path(sys.argv[1]).resolve(strict=True))

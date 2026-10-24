#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Executable adapter for consumers that expect a CLI binary path."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

source = Path(__file__).resolve().with_name("isolated-cli.py")
spec = importlib.util.spec_from_file_location("isolated_cli", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
binary = Path(os.environ["IRLUME_TEST_BINARY"])
receipts = Path(os.environ["IRLUME_TEST_RECEIPTS"])
with tempfile.NamedTemporaryFile(prefix="command-", suffix=".json", dir=receipts, delete=False) as receipt:
    result = module.run(binary, None, sys.argv[1:], Path(receipt.name))
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    raise SystemExit(result.returncode)

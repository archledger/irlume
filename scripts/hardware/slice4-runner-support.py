#!/usr/bin/env python3
"""Process-isolated locking and durability primitives for the slice-4 runner."""

import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys


LOCK_BUSY = 75


def hold_lock(lock_path: str, command: list[str]) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    lock_fd = os.open(lock_path, flags)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(
                "hardware-run: another slice-4 hardware run owns this host",
                file=sys.stderr,
            )
            return LOCK_BUSY

        child = None
        pending_signals = []
        previous_handlers = {}

        def forward(signum: int, _frame: object) -> None:
            if child is None:
                pending_signals.append(signum)
            elif child.poll() is None:
                child.send_signal(signum)

        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, forward)
        try:
            child = subprocess.Popen(command, close_fds=True)
            for signum in pending_signals:
                if child.poll() is None:
                    child.send_signal(signum)
            status = child.wait()
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        return status if status >= 0 else 128 - status
    finally:
        os.close(lock_fd)


def durable_evidence(paths: list[str]) -> int:
    for index, path in enumerate(paths):
        flags = os.O_RDONLY | os.O_CLOEXEC
        if index > 0 and hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return 0


def main(argv: list[str]) -> int:
    try:
        if len(argv) >= 4 and argv[1] == "hold-lock":
            return hold_lock(argv[2], argv[3:])
        if len(argv) == 6 and argv[1] == "durable-evidence":
            return durable_evidence(argv[2:])
    except OSError as error:
        print(f"hardware-run: support operation failed: {error}", file=sys.stderr)
        return 1
    print(
        f"usage: {Path(argv[0]).name} hold-lock LOCK_PATH COMMAND [ARG ...] | "
        "durable-evidence EVIDENCE RUN_DIR OUTPUT_DIR SOURCE_WORKTREE",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

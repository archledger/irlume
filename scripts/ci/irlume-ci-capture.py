#!/usr/bin/python3 -I
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Root-installed, source-bound, digest-pinned IR capture for a restricted CI account.

The administrator installs this file and an approved ELF separately. No caller
path, command, environment, frame count or output directory is accepted. Stdout
is a tar archive of capture files; diagnostics go to stderr.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

BASE = Path('/usr/local/lib/irlume-ci')
MANIFEST = BASE / 'capture.json'
BINARY = BASE / 'burst_dump'
SCRATCH = Path('/var/lib/irlume-ci')
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


def trusted_metadata(path, *, directory=False):
    """Reject symlinks and any path component writable by a non-root user."""
    for current in [path, *path.parents]:
        info = current.lstat()
        is_dir = directory if current == path else True
        expected = stat.S_ISDIR if is_dir else stat.S_ISREG
        if not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError(f'untrusted installed path: {current}')


def approved_binary(tree, device):
    if not re.fullmatch(r'[0-9a-f]{40}', tree):
        raise ValueError('expected one Git source-tree identity')
    if not re.fullmatch(r'/dev/video[0-9]{1,3}', device):
        raise ValueError('expected a video device path')
    trusted_metadata(MANIFEST)
    if MANIFEST.stat().st_size > 4096:
        raise ValueError('capture manifest is oversized')
    config = json.loads(MANIFEST.read_text())
    if config.get('schema') != 1 or config.get('source_tree') != tree:
        raise ValueError('capture build is not approved; an administrator must promote it')
    if config.get('device') != device:
        raise ValueError('capture device is not approved')
    digest = config.get('sha256', '')
    if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('approved executable digest is invalid')
    trusted_metadata(BINARY)
    fd = os.open(BINARY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            raise ValueError('untrusted capture executable')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            if stream.read(4) != b'\x7fELF':
                raise ValueError('approved capture must be an ELF executable')
            stream.seek(0)
            if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                raise ValueError('approved capture executable digest changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def archive_paths(output):
    """Emit only bounded, regular capture files with fixed, flat names."""
    paths = sorted(output.iterdir())
    frames = []
    total = 0
    for path in paths:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('capture output is not a standalone regular file')
        if path.name != 'means.txt':
            if not re.fullmatch(r'frame0[0-5]\.pgm', path.name):
                raise ValueError('unexpected capture output name')
            frames.append(path)
        total += info.st_size
    if not 4 <= len(frames) <= 6 or not (output / 'means.txt').is_file():
        raise ValueError('capture output is incomplete')
    if total > MAX_ARCHIVE_BYTES:
        raise ValueError('capture output exceeds the size limit')
    return paths


def capture_proof(diagnostic):
    """Require exactly one positive outcome; an already-held value is neither."""
    markers = {'irlume: capture emitter write completed': 'write',
               'irlume: capture emitter device default verified': 'default'}
    proofs = [markers[line] for line in diagnostic.splitlines() if line in markers]
    if len(proofs) != 1:
        raise ValueError('capture needs exactly one emitter write or verified device-default proof')
    return proofs[0]


def capture(tree, device):
    if os.geteuid() != 0:
        raise ValueError('capture helper requires root through its scoped sudo rule')
    os.umask(0o077)
    fd = approved_binary(tree, device)
    try:
        trusted_metadata(SCRATCH, directory=True)
        with tempfile.TemporaryDirectory(prefix='capture-', dir=SCRATCH) as name:
            output = Path(name)
            # Execute the same inode we hashed, even during an administrator's
            # atomic upgrade. Never forward the caller's loader or Irlume env.
            result = subprocess.run(
                [f'/proc/self/fd/{fd}', str(output), device, '6'],
                pass_fds=(fd,), cwd=output,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                     'IRLUME_LOG_EMITTER_WRITES': '1'},
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                timeout=45, check=False,
            )
            diagnostic = result.stderr.decode('utf-8', errors='replace')
            sys.stderr.write(diagnostic[-16384:])
            if result.returncode:
                raise ValueError(f'approved capture failed: exit {result.returncode}')
            capture_proof(diagnostic)
            paths = archive_paths(output)
            with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as archive:
                for path in paths:
                    archive.add(path, arcname=path.name, recursive=False)
    finally:
        os.close(fd)


def main():
    if len(sys.argv) != 3:
        print('usage: irlume-ci-capture SOURCE_TREE /dev/videoN', file=sys.stderr)
        return 2
    try:
        capture(*sys.argv[1:])
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'irlume-ci-capture: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

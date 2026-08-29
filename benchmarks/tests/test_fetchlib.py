import datetime
import hashlib
import zipfile
from pathlib import Path

import pytest

from fetchlib import (
    manifest_lines,
    parse_manifest,
    range_header,
    render_provenance,
    safe_extract_zip,
    sha256_file,
)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_sha256_file_matches_hashlib(tmp_path):
    p = _write(tmp_path, "f.bin", b"hello world")
    assert sha256_file(p) == hashlib.sha256(b"hello world").hexdigest()


def test_manifest_roundtrip_is_sorted():
    lines = manifest_lines({"b.bin": "bb" * 32, "a.bin": "aa" * 32})
    assert lines == "aa" * 32 + "  a.bin\n" + "bb" * 32 + "  b.bin\n"
    assert parse_manifest(lines) == {"a.bin": "aa" * 32, "b.bin": "bb" * 32}


def test_range_header_zero_and_nonzero():
    assert range_header(0) == {}
    assert range_header(1234) == {"Range": "bytes=1234-"}


def _zip_with(tmp_path: Path, members: dict[str, bytes]) -> Path:
    zp = tmp_path / "a.zip"
    with zipfile.ZipFile(zp, "w") as z:
        for n, d in members.items():
            z.writestr(n, d)
    return zp


def test_safe_extract_strips_single_top_dir(tmp_path):
    zp = _zip_with(tmp_path, {"top/sub/one.txt": b"1", "top/two.txt": b"22"})
    dest = tmp_path / "out"
    n = safe_extract_zip(zp, dest)
    assert n == 2
    assert (dest / "sub" / "one.txt").read_bytes() == b"1"
    assert (dest / "two.txt").read_bytes() == b"22"


def test_safe_extract_rejects_traversal(tmp_path):
    zp = _zip_with(tmp_path, {"../evil.txt": b"x"})
    with pytest.raises(ValueError):
        safe_extract_zip(zp, tmp_path / "out2")


def test_safe_extract_rejects_absolute_members(tmp_path):
    zp = _zip_with(tmp_path, {"/etc/evil.txt": b"x"})
    with pytest.raises(ValueError):
        safe_extract_zip(zp, tmp_path / "out3")


def test_safe_extract_enforces_total_budget(tmp_path):
    zp = _zip_with(tmp_path, {"big.bin": b"x" * 1000})
    with pytest.raises(ValueError):
        safe_extract_zip(zp, tmp_path / "out4", max_total_uncompressed=100)


def test_render_provenance_is_deterministic_markdown(tmp_path):
    from datasets import get_dataset

    spec = get_dataset("wider_face")
    fixed = datetime.datetime(2026, 8, 30, 12, 0, 0, tzinfo=datetime.UTC)
    md1 = render_provenance(
        spec, {"data/WIDER_val.zip": "ab" * 32}, "TERMS", now=fixed
    )
    md2 = render_provenance(
        spec, {"data/WIDER_val.zip": "ab" * 32}, "TERMS", now=fixed
    )
    assert md1 == md2
    assert "downloaded (UTC): 2026-08-30T12:00:00+00:00" in md1
    assert "CUHK-CSE/wider_face" in md1
    assert "ab" * 32 in md1
    assert "TERMS" in md1
    assert "\u2014" not in md1

# Model Calibration Phase 0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the calibration campaign foundations on archhost: pinned GPU venv, a verified dataset fetcher, the full WIDER FACE download, and a smoke detection run producing the first committed result file.

**Architecture:** Scripts live in the repo under `benchmarks/` following the existing `bench_*.py` convention. Development and unit tests run on the ASUS workstation in a uv venv; execution (venv, datasets, models, smoke run) happens on archhost via ssh + rsync. `datasets.py` is a pure registry, `fetchlib.py` holds pure helpers, `fetch_data.py` is a thin CLI over both.

**Tech Stack:** Python 3.12 (uv-managed), onnxruntime-gpu 1.27.0 (CUDA, RTX 3060), OpenCV (YuNet via `cv2.FaceDetectorYN`, matching the existing benchmarks), requests (streaming + Range resume), pytest 8.

**Spec:** `docs/superpowers/specs/2026-08-30-model-calibration-campaign-design.md` (same branch; executors read both).

## Global Constraints

- Zero em dashes (U+2014) in every deliverable: code, docs, commit messages, PROVENANCE templates. Grep for `\u2014` before finishing any task.
- DCO trailer on every commit, exactly: `Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>`. Commits are GPG-signed (repo `commit.gpgsign=true`); if pinentry times out, ask the user to unlock the key in their terminal (`echo test | gpg --clearsign > /dev/null`), then retry.
- Never print, commit, or log secret values. Kaggle token is read from `~/.kaggle/api_token` or `KAGGLE_API_TOKEN`; HF token from `HF_TOKEN` or `~/.cache/huggingface/token`. Tokens live on archhost already (installed and verified 2026-08-30).
- Research-only datasets are for measurement only; nothing derived from them ships as weights.
- Archives are deleted after successful extraction unless `--keep-archives`.
- The user gates every dataset download start (bandwidth). Pause and ask before Task 6 and before any later large download.
- Work happens on branch `docs/calibration-campaign` in worktree `/home/wisbfime/irlume/.worktrees/calib-spec`. archhost is reached via `ssh archhost` (key auth configured).
- Development venv on ASUS: `.venv-bench/` in the worktree. The worktree's `.git` is a file, so excludes go in the MAIN repo: add `.venv-bench/` to `/home/wisbfime/irlume/.git/info/exclude` (one line), never to `.gitignore` in this PR.

---

### Task 1: Pinned requirements + venv bootstrap script

**Files:**
- Create: `benchmarks/requirements-bench.txt`
- Create: `benchmarks/setup_archhost.sh`

**Interfaces:**
- Consumes: nothing
- Produces: `requirements-bench.txt` consumed by Task 5 (archhost venv creation); `setup_archhost.sh` consumed by Task 5. Exact versions pinned here are the provenance baseline for every result JSON later.

- [ ] **Step 1: Write the requirements file**

Create `benchmarks/requirements-bench.txt` with exactly:

```
onnxruntime-gpu==1.27.0
opencv-python-headless==5.0.0
numpy>=2.0,<3
requests>=2.32,<3
pytest>=8
```

Rationale (goes in a comment header at the top of the file): onnxruntime-gpu is pinned to 1.27.0 because the committed `results-*.json` were produced with it (benchmarks/README.md, Environment section). If `opencv-python-headless==5.0.0` fails to resolve at install time, fall back to the newest 5.x and record the exact resolved version in every result JSON (`runtime.cvd` field, already planned in Task 7).

- [ ] **Step 2: Write the bootstrap script**

Create `benchmarks/setup_archhost.sh`:

```bash
#!/usr/bin/env bash
# Idempotent archhost bootstrap for the irlume calibration campaign.
# Creates the pinned Python 3.12 venv and installs requirements-bench.txt.
set -euo pipefail

VENV="${VENV:-$HOME/venvs/bench}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v uv >/dev/null 2>&1; then
    echo "uv not found. Install it first: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
    uv venv "$VENV" --python 3.12
fi

uv pip install --python "$VENV/bin/python" -r "$HERE/requirements-bench.txt"

"$VENV/bin/python" - <<'EOF'
import cv2, numpy, requests, pytest  # noqa: F401
import onnxruntime as ort
print("cv2", cv2.__version__)
print("numpy", numpy.__version__)
print("ort", ort.__version__, ort.get_available_providers())
EOF
echo "OK: $VENV ready"
```

- [ ] **Step 3: Verify the script is shell-clean**

Run: `bash -n benchmarks/setup_archhost.sh && shellcheck benchmarks/setup_archhost.sh 2>/dev/null || true`
Expected: no syntax errors; shellcheck findings (if the tool exists) reviewed and either fixed or justified.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/requirements-bench.txt benchmarks/setup_archhost.sh
git commit -S -m "bench: pinned bench requirements and archhost venv bootstrap

Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>"
```

---

### Task 2: Dataset registry (`datasets.py`)

**Files:**
- Create: `benchmarks/datasets.py`
- Test: `benchmarks/tests/test_datasets.py`
- Create: `benchmarks/tests/conftest.py`

**Interfaces:**
- Consumes: nothing
- Produces (used by Tasks 3, 6):
  - `@dataclass(frozen=True) DatasetFile`: `path: str` (path inside the source repo), `sha256_expected: str | None`, `extract: bool`, `size_hint_bytes: int | None`
  - `@dataclass(frozen=True) DatasetSpec`: `name: str`, `source: str` (`"hf"` or `"kaggle"`), `repo: str`, `files: tuple[DatasetFile, ...]`, `license_note: str`, `provenance_url: str`, `notes: str`
  - `get_dataset(name: str) -> DatasetSpec` (raises `KeyError` with the unknown name plus `list_datasets()` in the message)
  - `list_datasets() -> tuple[str, ...]` (sorted)

- [ ] **Step 1: Write conftest so tests can import from benchmarks/**

Create `benchmarks/tests/conftest.py`:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
```

- [ ] **Step 2: Write the failing tests**

Create `benchmarks/tests/test_datasets.py`:

```python
import pytest

from datasets import DatasetFile, DatasetSpec, get_dataset, list_datasets


def test_wider_face_spec_is_complete():
    spec = get_dataset("wider_face")
    assert spec.source == "hf"
    assert spec.repo == "CUHK-CSE/wider_face"
    paths = {f.path for f in spec.files}
    assert "data/WIDER_train.zip" in paths
    assert "data/WIDER_val.zip" in paths
    assert "data/wider_face_split.zip" in paths
    assert all(f.extract for f in spec.files)
    assert spec.provenance_url.startswith("https://huggingface.co/datasets/")
    assert "research" in spec.license_note.lower()
    assert spec.notes


def test_every_entry_has_required_fields():
    for name in list_datasets():
        spec = get_dataset(name)
        assert spec.name == name
        assert spec.source in ("hf", "kaggle")
        assert spec.repo
        assert spec.files
        assert spec.license_note
        assert spec.provenance_url
        assert spec.notes


def test_unknown_name_raises_keyerror_with_candidates():
    with pytest.raises(KeyError) as e:
        get_dataset("no_such_set")
    assert "no_such_set" in str(e.value)
    assert "wider_face" in str(e.value)


def test_expected_hashes_are_64_hex_or_none():
    for name in list_datasets():
        for f in get_dataset(name).files:
            if f.sha256_expected is not None:
                assert len(f.sha256_expected) == 64
                int(f.sha256_expected, 16)


def test_no_em_dashes_anywhere():
    import datasets as m
    import inspect
    src = inspect.getsource(m)
    assert "\u2014" not in src
```

- [ ] **Step 3: Run tests to verify they fail**

First-time dev setup (skip the first two commands if `.venv-bench` already exists):
```bash
uv venv .venv-bench --python 3.12 && uv pip install --python .venv-bench/bin/python pytest
echo '.venv-bench/' >> /home/wisbfime/irlume/.git/info/exclude
```
Run: `.venv-bench/bin/pytest benchmarks/tests/test_datasets.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'datasets'`

- [ ] **Step 4: Write the registry**

Create `benchmarks/datasets.py`:

```python
"""Dataset registry for the calibration campaign.

Each entry pins the exact mirror irlume measured (see benchmarks/README.md:
mirror identity changes numbers). Archives are downloaded, sha256-recorded,
extracted, then deleted unless --keep-archives.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DatasetFile:
    path: str
    sha256_expected: str | None = None
    extract: bool = True
    size_hint_bytes: int | None = None


@dataclass(frozen=True)
class DatasetSpec:
    name: str
    source: str  # "hf" | "kaggle"
    repo: str  # hf "owner/repo" or kaggle "owner/slug"
    files: tuple[DatasetFile, ...]
    license_note: str
    provenance_url: str
    notes: str


_WIDER = DatasetSpec(
    name="wider_face",
    source="hf",
    repo="CUHK-CSE/wider_face",
    files=(
        DatasetFile(
            path="data/wider_face_split.zip",
            extract=True,
            size_hint_bytes=3_500_000,
        ),
        DatasetFile(
            path="data/WIDER_val.zip",
            extract=True,
            size_hint_bytes=360_000_000,
        ),
        DatasetFile(
            path="data/WIDER_train.zip",
            extract=True,
            size_hint_bytes=1_470_000_000,
        ),
    ),
    license_note=(
        "WIDER FACE is provided by CUHK for non-commercial research; the "
        "exact terms stated on the source page are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://huggingface.co/datasets/CUHK-CSE/wider_face",
    notes=(
        "Upload by the originating lab (CUHK-CSE). Official zip structure: "
        "WIDER_val/images/<event>/*.jpg plus wider_face_split/ ground truth. "
        "WIDER_test.zip is intentionally omitted: test annotations are not "
        "public; the AP protocol evaluates on val."
    ),
)

_DATASETS: dict[str, DatasetSpec] = {_WIDER.name: _WIDER}


def get_dataset(name: str) -> DatasetSpec:
    try:
        return _DATASETS[name]
    except KeyError:
        known = ", ".join(sorted(_DATASETS))
        raise KeyError(f"unknown dataset {name!r}; known: {known}") from None


def list_datasets() -> tuple[str, ...]:
    return tuple(sorted(_DATASETS))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv-bench/bin/pytest benchmarks/tests/test_datasets.py -q`
Expected: PASS (5 tests)

- [ ] **Step 6: Commit**

```bash
git add benchmarks/datasets.py benchmarks/tests/conftest.py benchmarks/tests/test_datasets.py
git commit -S -m "bench: dataset registry with pinned wider_face mirror

Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>"
```

---

### Task 3: Fetch helper library (`fetchlib.py`)

**Files:**
- Create: `benchmarks/fetchlib.py`
- Test: `benchmarks/tests/test_fetchlib.py`

**Interfaces:**
- Consumes: `DatasetSpec`, `DatasetFile` from `datasets.py`
- Produces (used by Task 4):
  - `sha256_file(path: Path, chunk_size: int = 1 << 20) -> str`
  - `manifest_lines(hashes: dict[str, str]) -> str` (sorted by relpath, lines `"<64hex>  <relpath>"`, trailing newline)
  - `parse_manifest(text: str) -> dict[str, str]`
  - `range_header(bytes_on_disk: int) -> dict[str, str]` (`{}` when 0, else `Range: bytes=N-`)
  - `safe_extract_zip(zip_path: Path, dest: Path, max_total_uncompressed: int = 20 << 30) -> int` (rejects absolute paths and `..` members and oversized totals; returns member count; strips a single common top-level dir so contents land directly in `dest`)
  - `render_provenance(spec: DatasetSpec, hashes: dict[str, str], terms_quoted: str) -> str` (deterministic markdown, zero em dashes)

- [ ] **Step 1: Write the failing tests**

Create `benchmarks/tests/test_fetchlib.py`:

```python
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
    md1 = render_provenance(spec, {"data/WIDER_val.zip": "ab" * 32}, "TERMS")
    md2 = render_provenance(spec, {"data/WIDER_val.zip": "ab" * 32}, "TERMS")
    assert md1 == md2
    assert "CUHK-CSE/wider_face" in md1
    assert "ab" * 32 in md1
    assert "TERMS" in md1
    assert "\u2014" not in md1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv-bench/bin/pytest benchmarks/tests/test_fetchlib.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'fetchlib'`

- [ ] **Step 3: Write the implementation**

Create `benchmarks/fetchlib.py`:

```python
"""Pure helpers for the dataset fetcher: hashing, manifests, resume ranges,
zip-slip-guarded extraction, provenance rendering. No network I/O here.
"""

import hashlib
import zipfile
from pathlib import Path, PurePosixPath

from datasets import DatasetSpec

_MANIFEST_NAME = "MANIFEST.sha256"


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def manifest_lines(hashes: dict[str, str]) -> str:
    return "".join(f"{digest}  {rel}\n" for rel, digest in sorted(hashes.items()))


def parse_manifest(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        out[rel] = digest
    return out


def range_header(bytes_on_disk: int) -> dict[str, str]:
    return {} if bytes_on_disk <= 0 else {"Range": f"bytes={bytes_on_disk}-"}


def _member_is_safe(name: str) -> bool:
    p = PurePosixPath(name)
    if p.is_absolute() or name.startswith("/"):
        return False
    return ".." not in p.parts


def safe_extract_zip(
    zip_path: Path,
    dest: Path,
    max_total_uncompressed: int = 20 << 30,
) -> int:
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        for info in infos:
            if not _member_is_safe(info.filename):
                raise ValueError(f"unsafe zip member: {info.filename!r}")
            total += info.file_size
        if total > max_total_uncompressed:
            raise ValueError(
                f"zip expands to {total} bytes, over budget {max_total_uncompressed}"
            )
        top = {PurePosixPath(i.filename).parts[0] for i in infos}
        strip = len(top) == 1 and all(
            len(PurePosixPath(i.filename).parts) > 1 for i in infos
        )
        for info in infos:
            rel = info.filename
            if strip:
                rel = rel[len(list(top)[0]) + 1 :]
                if not rel:
                    continue
            target = dest / rel
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(1 << 20):
                    out.write(chunk)
    return len([i for i in infos if not i.is_dir()])


def render_provenance(
    spec: DatasetSpec,
    hashes: dict[str, str],
    terms_quoted: str,
) -> str:
    lines = [
        f"# PROVENANCE: {spec.name}",
        "",
        f"- source: {spec.source} repo {spec.repo}",
        f"- url: {spec.provenance_url}",
        f"- downloaded (UTC): {__import__('datetime').datetime.now(datetime.UTC).isoformat()}",
        f"- license note: {spec.license_note}",
        f"- terms quoted from source page: {terms_quoted}",
        f"- notes: {spec.notes}",
        "",
        "## Files (sha256)",
        "",
    ]
    for rel, digest in sorted(hashes.items()):
        lines.append(f"- {digest}  {rel}")
    lines.append("")
    return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv-bench/bin/pytest benchmarks/tests/test_fetchlib.py -q`
Expected: PASS (9 tests)

- [ ] **Step 5: Commit**

```bash
git add benchmarks/fetchlib.py benchmarks/tests/test_fetchlib.py
git commit -S -m "bench: fetch helper library with zip-slip guard and manifests

Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>"
```

---

### Task 4: Fetcher CLI (`fetch_data.py`)

**Files:**
- Create: `benchmarks/fetch_data.py`

**Interfaces:**
- Consumes: `datasets.get_dataset/list_datasets`, `fetchlib` (all functions above)
- Produces (used by Task 6):
  - CLI: `python3 fetch_data.py download <name> --root DIR [--only SUBSTR]... [--keep-archives] [--dry-run]`
  - CLI: `python3 fetch_data.py list`
  - `hf_url(repo: str, path: str) -> str` returns `https://huggingface.co/datasets/{repo}/resolve/main/{path}`
  - `kaggle_url(repo: str) -> str` returns `https://www.kaggle.com/api/v1/datasets/download/{repo}`
  - `load_token(env_var: str, file_path: Path) -> str | None` (env first, then file, stripped; never printed)
  - `download_file(url: str, dest: Path, session: requests.Session, headers_extra: dict[str, str] | None = None) -> int` (streams to `dest` with Range resume, returns bytes on disk after download)

- [ ] **Step 1: Write the implementation**

Create `benchmarks/fetch_data.py`:

```python
#!/usr/bin/env python3
"""Resumable dataset fetcher for the calibration campaign.

Downloads each DatasetSpec's files (HF resolve URLs or Kaggle REST download
endpoints), records MANIFEST.sha256, extracts archives (zip-slip guarded),
deletes archives, writes PROVENANCE.md.

Auth: HF token from HF_TOKEN or ~/.cache/huggingface/token; Kaggle token from
KAGGLE_API_TOKEN or ~/.kaggle/api_token. Tokens are never printed or logged.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import requests

from datasets import get_dataset, list_datasets
from fetchlib import (
    manifest_lines,
    parse_manifest,
    range_header,
    render_provenance,
    safe_extract_zip,
    sha256_file,
)

HF_HOST = "https://huggingface.co"
KAGGLE_HOST = "https://www.kaggle.com"


def hf_url(repo: str, path: str) -> str:
    return f"{HF_HOST}/datasets/{repo}/resolve/main/{path}"


def kaggle_url(repo: str) -> str:
    # Kaggle v1 REST downloads the WHOLE dataset archive per call, so a
    # kaggle-sourced DatasetSpec must define exactly one archive file.
    return f"{KAGGLE_HOST}/api/v1/datasets/download/{repo}"


def load_token(env_var: str, file_path: Path) -> str | None:
    tok = os.environ.get(env_var, "").strip()
    if tok:
        return tok
    if file_path.is_file():
        tok = file_path.read_text(encoding="utf-8").strip()
        return tok or None
    return None


def _existing_bytes(dest: Path) -> int:
    return dest.stat().st_size if dest.is_file() else 0


def download_file(
    url: str,
    dest: Path,
    session: requests.Session,
    headers_extra: dict[str, str] | None = None,
) -> int:
    dest.parent.mkdir(parents=True, exist_ok=True)
    headers = dict(headers_extra or {})
    headers.update(range_header(_existing_bytes(dest)))
    with session.get(url, headers=headers, stream=True, timeout=60, allow_redirects=True) as r:
        if r.status_code == 416:
            return _existing_bytes(dest)
        r.raise_for_status()
        mode = "ab" if r.status_code == 206 else "wb"
        if r.status_code == 206 and _existing_bytes(dest) == 0:
            mode = "wb"
        with open(dest, mode) as f:
            for chunk in r.iter_content(chunk_size=1 << 20):
                if chunk:
                    f.write(chunk)
    return _existing_bytes(dest)


def _terms_from_readme(spec, session: requests.Session) -> str:
    """Best-effort fetch of the source page's stated terms, quoted verbatim."""
    try:
        if spec.source == "hf":
            url = f"{HF_HOST}/datasets/{spec.repo}/raw/main/README.md"
        else:
            url = f"{KAGGLE_HOST}/api/v1/datasets/view/{spec.repo}"
        r = session.get(url, timeout=30)
        r.raise_for_status()
        text = r.text
        for kw in ("license", "License", "research", "terms"):
            idx = text.find(kw)
            if idx != -1:
                return text[max(0, idx - 100) : idx + 400].strip()[:500]
        return "(terms keywords not found in source README; quote manually)"
    except Exception as e:  # noqa: BLE001 - provenance capture must not kill downloads
        return f"(terms capture failed: {type(e).__name__}; quote manually)"


def download_dataset(
    spec_name: str,
    root: Path,
    only: list[str] | None = None,
    keep_archives: bool = False,
    session: requests.Session | None = None,
) -> dict:
    spec = get_dataset(spec_name)
    session = session or requests.Session()
    if spec.source == "hf":
        tok = load_token("HF_TOKEN", Path.home() / ".cache/huggingface/token")
        auth = {"Authorization": f"Bearer {tok}"} if tok else {}
    else:
        tok = load_token("KAGGLE_API_TOKEN", Path.home() / ".kaggle/api_token")
        if not tok:
            raise SystemExit("no Kaggle token: set KAGGLE_API_TOKEN or ~/.kaggle/api_token")
        auth = {"Authorization": f"Bearer {tok}"}

    ddir = root / spec.name
    archives = ddir / "_archives"
    archives.mkdir(parents=True, exist_ok=True)

    wanted = spec.files
    if only:
        wanted = tuple(f for f in spec.files if any(s in f.path for s in only))
        if not wanted:
            raise SystemExit(f"--only matched nothing in {spec.name}: {only}")

    if spec.source == "hf":
        urls = {f.path: hf_url(spec.repo, f.path) for f in wanted}
    else:
        urls = {f.path: kaggle_url(spec.repo) for f in wanted}

    for f in wanted:
        dest = archives / Path(f.path).name
        if f.sha256_expected and dest.is_file() and sha256_file(dest) == f.sha256_expected:
            print(f"already present and verified: {dest.name}")
            continue
        print(f"fetching {f.path} ...")
        n = download_file(urls[f.path], dest, session, auth)
        print(f"  {dest.name}: {n} bytes on disk")
        if f.sha256_expected:
            got = sha256_file(dest)
            if got != f.sha256_expected:
                raise SystemExit(f"sha mismatch for {dest.name}: expected {f.sha256_expected}, got {got}")

    hashes = {}
    for f in wanted:
        dest = archives / Path(f.path).name
        hashes[f.path] = sha256_file(dest)

    manifest_path = ddir / "MANIFEST.sha256"
    prior = parse_manifest(manifest_path.read_text()) if manifest_path.is_file() else {}
    prior.update(hashes)
    manifest_path.write_text(manifest_lines(prior))

    extracted = {}
    for f in wanted:
        if not f.extract:
            continue
        dest = archives / Path(f.path).name
        extracted[f.path] = safe_extract_zip(dest, ddir)
        if not keep_archives:
            dest.unlink()
        print(f"extracted {dest.name}: {extracted[f.path]} members")

    terms = _terms_from_readme(spec, session)
    (ddir / "PROVENANCE.md").write_text(render_provenance(spec, prior, terms))

    return {"dataset": spec.name, "files": sorted(hashes), "extracted": extracted}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("download")
    d.add_argument("name", help="dataset name; one of: " + ", ".join(list_datasets()))
    d.add_argument("--root", type=Path, required=True, help="datasets root, e.g. ~/datasets")
    d.add_argument("--only", action="append", default=[], help="substring filter on file paths")
    d.add_argument("--keep-archives", action="store_true")
    d.add_argument("--dry-run", action="store_true", help="print the plan, touch nothing")
    sub.add_parser("list")
    args = ap.parse_args(argv)

    if args.cmd == "list":
        for n in list_datasets():
            s = get_dataset(n)
            print(f"{n}  {s.source}:{s.repo}  files={len(s.files)}")
        return 0

    spec = get_dataset(args.name)
    if args.dry_run:
        for f in spec.files:
            print(f"would fetch {f.path} (~{f.size_hint_bytes} bytes)")
        return 0
    summary = download_dataset(args.name, args.root, args.only or None, args.keep_archives)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Offline CLI tests (dry-run and list)**

Run:
```bash
.venv-bench/bin/python benchmarks/fetch_data.py list
.venv-bench/bin/python benchmarks/fetch_data.py download wider_face --root /tmp/opencode/dsroot --dry-run
```
Expected: `list` prints the wider_face row; `dry-run` prints the three planned files, touches nothing (`/tmp/opencode/dsroot` not created).

- [ ] **Step 3: Live micro-download verification (tiny file only, HF path)**

Run:
```bash
.venv-bench/bin/python benchmarks/fetch_data.py download wider_face --root /tmp/opencode/dsroot --only wider_face_split
```
Expected: downloads `wider_face_split.zip` (~3.5MB) via Bearer auth, extracts to `/tmp/opencode/dsroot/wider_face/wider_face_split/` (bbox txt files present), archives deleted, `MANIFEST.sha256` and `PROVENANCE.md` written. Verify: `ls /tmp/opencode/dsroot/wider_face/wider_face_split/` shows `wider_face_train_bbx_gt.txt` and `wider_face_val_bbx_gt.txt`.

- [ ] **Step 4: Commit**

```bash
git add benchmarks/fetch_data.py
git commit -S -m "bench: resumable dataset fetcher CLI with manifest and provenance

Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>"
```

---

### Task 5: archhost deployment + venv + models verification

**Files:**
- No repo file changes. Deployment and host-side verification only.

**Interfaces:**
- Consumes: Tasks 1 to 4 outputs (requirements, bootstrap script, fetcher, registry)
- Produces: on archhost, `~/irlume-bench/` containing `benchmarks/` + verified `models/`; `~/venvs/bench` Python 3.12 venv with all pinned packages. Later tasks run inside this layout.

- [ ] **Step 1: Deploy the working tree subset to archhost**

Run (from the worktree root):
```bash
ssh archhost 'mkdir -p ~/irlume-bench'
rsync -a benchmarks/ archhost:irlume-bench/benchmarks/
rsync -a --delete --exclude '.venv-bench' --exclude '__pycache__' benchmarks/ archhost:irlume-bench/benchmarks/
```
Expected: clean rsync, no errors.

- [ ] **Step 2: Bootstrap the venv on archhost**

Run:
```bash
ssh archhost 'bash ~/irlume-bench/benchmarks/setup_archhost.sh'
```
Expected: ends with `OK: /home/archledger/venvs/bench ready` and prints cv2/numpy versions plus ORT providers including `CUDAExecutionProvider`. If `opencv-python-headless==5.0.0` does not resolve, switch the pin to the newest resolvable 5.x, record the resolved version, and amend the requirements file (new commit) before continuing.

- [ ] **Step 3: Deploy and verify the six shipped models**

Run:
```bash
rsync -a /home/wisbfime/irlume/models/ archhost:irlume-bench/models/
ssh archhost 'cd ~/irlume-bench/models && sha256sum -c SHA256SUMS'
```
Expected: every line `OK`. Any mismatch aborts the phase (model integrity is the provenance baseline).

- [ ] **Step 4: Record host facts for the result files**

Run:
```bash
ssh archhost 'nvidia-smi --query-gpu=name,driver_version --format=csv,noheader; ~/venvs/bench/bin/python -c "import onnxruntime as ort; print(ort.__version__, ort.get_available_providers())"'
```
Expected: RTX 3060 + driver line; ORT 1.27.0 with CUDAExecutionProvider listed. Save the output; Task 7 embeds it in the result JSON's `runtime` block.

---

### Task 6: WIDER FACE full download on archhost (USER GATE)

**Files:**
- No repo changes. Produces `~/datasets/wider_face/` on archhost.

**Interfaces:**
- Consumes: Task 4 fetcher, Task 5 layout
- Produces: verified extracted WIDER train+val+split at `~/datasets/wider_face/` with `MANIFEST.sha256` + `PROVENANCE.md`; consumed by Task 7 and every later detection task.

- [ ] **Step 1: USER GATE: ask before downloading**

Ask the user to confirm the download: about 1.83 GB of zips (1.47 train + 0.36 val + 0.0035 split) from huggingface.co, extracted to roughly 2 GB on archhost. Do not start without a yes.

- [ ] **Step 2: Dry-run, then fetch annotations first (tiny validation of the full chain on archhost)**

Run:
```bash
ssh archhost '~/venvs/bench/bin/python ~/irlume-bench/benchmarks/fetch_data.py download wider_face --root ~/datasets --only wider_face_split'
ssh archhost 'ls ~/datasets/wider_face/wider_face_split/ | head'
```
Expected: split zip downloaded, extracted, `wider_face_train_bbx_gt.txt` and `wider_face_val_bbx_gt.txt` present.

- [ ] **Step 3: Fetch the two image zips (resumable; safe to re-run if interrupted)**

Run:
```bash
ssh archhost '~/venvs/bench/bin/python ~/irlume-bench/benchmarks/fetch_data.py download wider_face --root ~/datasets'
```
Expected: `WIDER_val.zip` then `WIDER_train.zip` fetched, manifests updated, archives deleted. Interruptions resume via Range headers on re-run.

- [ ] **Step 4: Verify the extraction shape**

Run:
```bash
ssh archhost 'ls ~/datasets/wider_face/; ls ~/datasets/wider_face/WIDER_val/images | head -3; grep -c "\.jpg" ~/datasets/wider_face/wider_face_split/wider_face_val_bbx_gt.txt; grep -c "\.jpg" ~/datasets/wider_face/wider_face_split/wider_face_train_bbx_gt.txt'
```
Expected: `MANIFEST.sha256`, `PROVENANCE.md`, `_archives/`, `WIDER_val/`, `WIDER_train/`, `wider_face_split/`; event directories under `WIDER_val/images`; the official image counts are **3,226 val** and **12,880 train** (.jpg entries in each GT file). If either count differs, stop and investigate the mirror before proceeding.

---

### Task 7: Smoke detection run (`bench_detection_wider.py --smoke`)

**Files:**
- Create: `benchmarks/bench_detection_wider.py`
- Create: `benchmarks/results-smoke-wider.json` (committed output)

**Interfaces:**
- Consumes: Task 5 models dir (YuNet at `~/irlume-bench/models/face_detection_yunet_2023mar.onnx`), Task 6 dataset (`~/datasets/wider_face/`), archhost venv
- Produces: `results-smoke-wider.json`, schema: `{"runtime": {"ort_version": str, "providers": [str], "cv2_version": str, "gpu": str}, "protocol": {"smoke": true, "n": int, "source": "wider_face val, first N images of the sorted bbox ground truth"}, "per_image": [{"file": str, "n_faces": int, "max_score": float}], "summary": {"images": int, "total_faces": int, "images_with_zero_faces": int}}`. Phase 1's plan extends this file's script with full AP; the JSON schema above is its base.

- [ ] **Step 1: Write the script**

Create `benchmarks/bench_detection_wider.py`:

```python
#!/usr/bin/env python3
"""YuNet detection benchmark on WIDER FACE.

--smoke: run the first N images of the sorted val ground truth through YuNet
at irlume operating scale and write per-image counts. Full AP evaluation is a
later phase; this smoke run exists to prove the chain (venv, CUDA, models,
dataset, OpenCV YuNet) end to end.
"""

import argparse
import json
import sys
from pathlib import Path

import cv2
import onnxruntime as ort


def val_image_list(wider_root: Path) -> list[str]:
    gt = wider_root / "wider_face_split" / "wider_face_val_bbx_gt.txt"
    out = []
    for line in gt.read_text().splitlines():
        if line.endswith(".jpg"):
            out.append(line.strip())
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--models-dir", type=Path, required=True)
    ap.add_argument("--wider-root", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--n", type=int, default=32, help="smoke image count")
    args = ap.parse_args(argv)

    det = cv2.FaceDetectorYN_create(
        str(args.models_dir / "face_detection_yunet_2023mar.onnx"),
        "",
        (320, 240),
        score_threshold=0.6,
    )
    vals = val_image_list(args.wider_root)
    images = vals[: args.n] if args.smoke else vals
    per_image = []
    for rel in images:
        img = cv2.imread(str(args.wider_root / "WIDER_val" / "images" / rel))
        if img is None:
            per_image.append({"file": rel, "n_faces": -1, "max_score": 0.0})
            continue
        h, w = img.shape[:2]
        det.setInputSize((w, h))
        ret, faces = det.detect(img)
        if faces is None:
            n, mx = 0, 0.0
        else:
            n = int(faces.shape[0])
            mx = float(faces[:, 14].max())
        per_image.append({"file": rel, "n_faces": n, "max_score": round(mx, 4)})

    ok = [p for p in per_image if p["n_faces"] >= 0]
    result = {
        "runtime": {
            "ort_version": ort.__version__,
            "providers": ort.get_available_providers(),
            "cv2_version": cv2.__version__,
        },
        "protocol": {
            "smoke": bool(args.smoke),
            "n": len(images),
            "source": "wider_face val, first N images of the sorted bbox ground truth",
        },
        "per_image": per_image,
        "summary": {
            "images": len(ok),
            "total_faces": sum(p["n_faces"] for p in ok),
            "images_with_zero_faces": sum(1 for p in ok if p["n_faces"] == 0),
        },
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Local import check (no dataset needed)**

Run: `.venv-bench/bin/python -c "import ast; ast.parse(open('benchmarks/bench_detection_wider.py').read())"`
Expected: no output (parses). Full runtime check happens on archhost only (dataset lives there).

- [ ] **Step 3: Deploy and run the smoke on archhost**

Run:
```bash
rsync -a --exclude '__pycache__' benchmarks/bench_detection_wider.py archhost:irlume-bench/benchmarks/
ssh archhost '~/venvs/bench/bin/python ~/irlume-bench/benchmarks/bench_detection_wider.py --models-dir ~/irlume-bench/models --wider-root ~/datasets/wider_face --out ~/irlume-bench/benchmarks/results-smoke-wider.json --smoke --n 32'
```
Expected: prints a summary JSON line; 32 images processed; zero-face count small (single digits at most on WIDER val with YuNet at 0.6). Fetch the result back:
```bash
rsync -a archhost:irlume-bench/benchmarks/results-smoke-wider.json benchmarks/
```

- [ ] **Step 4: Sanity-check the result before committing**

Run: `python3 -c "import json; d=json.load(open('benchmarks/results-smoke-wider.json')); print(d['runtime']['providers']); print(d['summary'])"`
Expected: providers include CUDAExecutionProvider; summary shows 32 images. If the ASUS dev box lacks cv2, this check runs on archhost instead.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/bench_detection_wider.py benchmarks/results-smoke-wider.json
git commit -S -m "bench: wider face smoke detection run, first committed campaign result

Signed-off-by: Wisbendji Fimerlus <archledger236@gmail.com>"
```

---

## Phase 0 exit criteria

- `benchmarks/` carries: `requirements-bench.txt`, `setup_archhost.sh`, `datasets.py`, `fetchlib.py`, `fetch_data.py`, `bench_detection_wider.py`, `tests/` (all green under the dev venv), `results-smoke-wider.json`.
- archhost carries: `~/venvs/bench` (3.12, CUDA-capable ORT 1.27.0), verified `~/irlume-bench/models/`, downloaded and verified `~/datasets/wider_face/`.
- Unit tests: `.venv-bench/bin/pytest benchmarks/tests -q` all pass.
- Every commit GPG-signed with the exact DCO trailer; zero em dashes across all new files (verify: `grep -rP "\x{2014}" benchmarks/ | wc -l` prints 0).
- Branch is ready to PR as `docs/calibration-campaign` (spec + plan + Phase 0 together) or to continue accumulating Phase 1; the user decides at phase end.

## Out of scope for Phase 0 (later phase plans)

- Full WIDER AP evaluation and cascade rescue-rate protocol (Phase 1).
- WFLW/300W/AFLW2000 landmark tracks (Phase 1).
- Recognition suite, PAD tracks, CelebA-Spoof acquisition, calibration synthesis, replacement-candidate tables (Phases 2 to 4).

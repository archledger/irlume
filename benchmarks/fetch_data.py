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

from datasets import DatasetSpec, get_dataset, list_datasets
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


def validate_spec(spec: DatasetSpec) -> None:
    if spec.source == "kaggle" and len(spec.files) != 1:
        raise SystemExit(
            f"{spec.name}: kaggle specs must define exactly one archive "
            f"file, got {len(spec.files)}"
        )


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
    validate_spec(spec)
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

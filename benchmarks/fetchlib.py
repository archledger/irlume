"""Pure helpers for the dataset fetcher: hashing, manifests, resume ranges,
zip-slip-guarded extraction, provenance rendering. No network I/O here.
"""

import datetime
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
    spec,
    hashes,
    terms_quoted,
    now=None,
):
    stamp = now or datetime.datetime.now(datetime.UTC)
    stamp = stamp.replace(microsecond=0)
    lines = [
        f"# PROVENANCE: {spec.name}",
        "",
        f"- source: {spec.source} repo {spec.repo}",
        f"- url: {spec.provenance_url}",
        f"- downloaded (UTC): {stamp.isoformat()}",
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

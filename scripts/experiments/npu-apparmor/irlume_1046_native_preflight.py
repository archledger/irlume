"""Static ELF/ownership primitives; no native object is loaded by this module."""

import hashlib
import re
import stat
import subprocess
from collections import deque
from pathlib import Path

from elftools.elf.elffile import ELFFile


def trusted_path(path, roots, owner=0, *, anchor=Path("/")):
    path, anchor = Path(path), Path(anchor)
    if not path.is_absolute() or not path.is_relative_to(anchor):
        raise ValueError("path is outside the trust anchor")
    base = anchor.lstat()
    if not stat.S_ISDIR(base.st_mode) or base.st_uid != owner or base.st_mode & 0o022:
        raise ValueError("untrusted anchor")
    pending = deque(path.relative_to(anchor).parts)
    current = anchor
    links = 0
    while pending:
        part = pending.popleft()
        if part == ".":
            continue
        if part == "..":
            if current == anchor:
                raise ValueError("path escapes the trust anchor")
            current = current.parent
            continue
        entry = current / part
        metadata = entry.lstat()
        if metadata.st_uid != owner:
            raise ValueError("wrong path owner")
        if stat.S_ISLNK(metadata.st_mode):
            links += 1
            if links > 40:
                raise ValueError("too many aliases")
            target = entry.readlink()
            if target.is_absolute():
                if not target.is_relative_to(anchor):
                    raise ValueError("alias escapes the trust anchor")
                current = anchor
                target = target.relative_to(anchor)
            pending.extendleft(reversed(target.parts))
        else:
            if metadata.st_mode & 0o022:
                raise ValueError("writable native path")
            if pending and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("non-directory path component")
            current = entry
    if not current.is_file() or not any(
        current.is_relative_to(Path(root)) for root in roots
    ):
        raise ValueError("native endpoint is outside approved roots")
    return current


def elf_metadata(path):
    path = Path(path)
    if path.stat().st_size > 512 * 1024**2:
        raise ValueError("native file exceeds the bound")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if (
            elf.elfclass != 64
            or not elf.little_endian
            or elf["e_machine"] != "EM_X86_64"
        ):
            raise ValueError("unexpected ELF architecture")
        needed, search, search_tags, interpreters = [], [], [], []
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_INTERP":
                interpreters.append(segment.get_interp_name())
            elif segment["p_type"] == "PT_DYNAMIC":
                for tag in segment.iter_tags():
                    name = tag.entry.d_tag
                    if name == "DT_NEEDED":
                        needed.append(tag.needed)
                    elif name in ("DT_RPATH", "DT_RUNPATH"):
                        search.append(
                            getattr(tag, "rpath" if name == "DT_RPATH" else "runpath")
                        )
                        search_tags.append(name)
                    elif name in (
                        "DT_FILTER",
                        "DT_AUXILIARY",
                        "DT_AUDIT",
                        "DT_DEPAUDIT",
                    ):
                        raise ValueError("unsupported dynamic loader hook")
        if len(interpreters) > 1:
            raise ValueError("multiple ELF interpreters")
        return {
            "needed": needed,
            "search": search,
            "search_tags": search_tags,
            "interpreter": interpreters[0] if interpreters else None,
        }


def resolve_closure(seeds, cache, inspect, *, maximum=512, allow_search=None):
    pending = list(seeds)
    result = {}
    while pending:
        path = pending.pop()
        if path in result:
            continue
        if len(result) >= maximum:
            raise ValueError("native closure exceeds the bound")
        metadata = inspect(path)
        if metadata["search"] and (
            allow_search is None or not allow_search(path, metadata)
        ):
            raise ValueError("unreviewed RPATH/RUNPATH")
        result[path] = metadata
        interpreter = metadata.get("interpreter")
        if interpreter:
            if not interpreter.startswith("/"):
                raise ValueError("relative interpreter")
            pending.append(interpreter)
        for name in metadata["needed"]:
            if not name or "/" in name or name in (".", ".."):
                raise ValueError("non-soname dependency")
            candidates = set(cache.get(name, []))
            if len(candidates) != 1:
                raise ValueError("missing or ambiguous native dependency: " + name)
            pending.append(candidates.pop())
    return result


def allow_pinned_ort_origin(path, metadata, digest, files, aliases):
    expected = {
        "libonnxruntime.so.1.28.1": "e38d2cec3d582c41786bdd428865fc017145599666cb7c82410e52496e7e066d",
        "libonnxruntime_providers_shared.so": "086ec1d5388f64153d9c63470d126693db9a182c8ce236d3a1119068471b8a0d",
    }
    return (
        path == "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1"
        and digest == expected["libonnxruntime.so.1.28.1"]
        and metadata["search"] == ["$ORIGIN"]
        and metadata.get("search_tags") == ["DT_RUNPATH"]
        and files == expected
        and aliases == {"libonnxruntime.so.1": "libonnxruntime.so.1.28.1"}
        and not set(metadata["needed"]).intersection(set(files) | set(aliases))
    )


def resolve_seeds(seeds, cache, canonicalize):
    result = []
    if len(seeds) > 128:
        raise ValueError("too many dynamic lookup seeds")
    for seed in seeds:
        if not isinstance(seed, dict) or set(seed) != {"lookup", "canonical"}:
            raise ValueError("dynamic seed must declare lookup and canonical endpoint")
        lookup, expected = seed["lookup"], seed["canonical"]
        if (
            not isinstance(lookup, str)
            or not isinstance(expected, str)
            or not expected.startswith("/")
        ):
            raise ValueError("invalid dynamic lookup seed")
        if canonicalize(expected) != expected:
            raise ValueError("declared endpoint is not canonical")
        if lookup.startswith("/"):
            actual = canonicalize(lookup)
        else:
            if not lookup or "/" in lookup:
                raise ValueError("invalid dynamic lookup name")
            candidates = {canonicalize(path) for path in cache.get(lookup, [])}
            if len(candidates) != 1:
                raise ValueError("missing or ambiguous dynamic lookup: " + lookup)
            actual = candidates.pop()
        if actual != expected:
            raise ValueError("dynamic lookup resolved to another endpoint")
        if actual not in result:
            result.append(actual)
    return result


def validate_environment(environment):
    fixed = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "HOME": "/",
        "ORT_DYLIB_PATH": "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1",
    }
    if set(environment) != set(fixed) | {"IRLUME_NPU_AA_CASE"}:
        raise ValueError("unexpected or missing process environment")
    if any(environment[key] != value for key, value in fixed.items()):
        raise ValueError("unexpected process environment value")
    if environment["IRLUME_NPU_AA_CASE"] not in ("bin-native", "local-native"):
        raise ValueError("unknown test case")


def guest_closure(binary, native_seeds):
    """Read a pristine guest's loader inventory; this does not execute binary."""
    binary = str(binary)
    if binary not in ("/usr/bin/irlumed", "/usr/local/bin/irlumed"):
        raise ValueError("unexpected test executable")
    if Path("/etc/ld.so.preload").exists() or Path("/etc/ld.so.preload").is_symlink():
        raise ValueError("loader preload file exists")
    library_roots = [
        Path("/usr/lib"),
        Path("/usr/lib64"),
        Path("/opt/irlume/onnxruntime/lib"),
    ]

    def canonical(path):
        roots = [Path(binary).parent] if str(path) == binary else library_roots
        return str(trusted_path(path, roots))

    output = subprocess.check_output(["/sbin/ldconfig", "-p"], text=True, timeout=10)
    cache = {}
    for line in output.splitlines():
        match = re.fullmatch(r"\s*(\S+) \(([^)]+)\) => (/\S+)\s*", line)
        if match and "x86-64" in match[2]:
            cache.setdefault(match[1], []).append(match[3])

    # Canonicalize only dependencies used by this closure; unrelated cache rows
    # are neither executed nor evidence about the selected runtime.
    class ResolvedCache(dict):
        def get(self, name, default=None):
            return [canonical(path) for path in cache.get(name, [])]

    records = {}

    def inspect(path):
        real = canonical(path)
        metadata = elf_metadata(real)
        with Path(real).open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        records[real] = {
            "sha256": digest,
            "bytes": Path(real).stat().st_size,
            **metadata,
        }
        return metadata

    def allow_search(path, metadata):
        real = canonical(path)
        if real != "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1":
            return False
        folder = Path(real).parent
        files = {}
        aliases = {}
        # Accept only the pinned SONAME alias that ldconfig maintains.
        entries = list(folder.iterdir())
        if len(entries) != 3:
            return False
        for entry in entries:
            if entry.is_symlink():
                if (
                    entry.name != "libonnxruntime.so.1"
                    or str(entry.readlink()) != "libonnxruntime.so.1.28.1"
                ):
                    return False
                if (
                    trusted_path(entry, library_roots)
                    != folder / "libonnxruntime.so.1.28.1"
                ):
                    return False
                aliases[entry.name] = str(entry.readlink())
                continue
            if not entry.is_file():
                return False
            trusted_path(entry, library_roots)
            with entry.open("rb") as stream:
                files[entry.name] = hashlib.file_digest(stream, "sha256").hexdigest()
        return allow_pinned_ort_origin(
            real, metadata, records[real]["sha256"], files, aliases
        )

    resolved_seeds = resolve_seeds(native_seeds, ResolvedCache(), canonical)
    graph = resolve_closure(
        [binary, *resolved_seeds], ResolvedCache(), inspect, allow_search=allow_search
    )
    cache_path = trusted_path("/etc/ld.so.cache", [Path("/etc")])
    with cache_path.open("rb") as stream:
        cache_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "files": records,
        "edges": graph,
        "dynamic_lookups": native_seeds,
        "loader_cache_sha256": cache_hash,
    }

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from irlume_1046_native_preflight import (
    allow_pinned_ort_origin,
    elf_metadata,
    resolve_closure,
    resolve_seeds,
    trusted_path,
    validate_environment,
)


class NativePreflightTests(unittest.TestCase):
    def test_only_pinned_nonshadowing_ort_origin_is_accepted(self):
        path = "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1"
        digest = "e38d2cec3d582c41786bdd428865fc017145599666cb7c82410e52496e7e066d"
        files = {
            "libonnxruntime.so.1.28.1": digest,
            "libonnxruntime_providers_shared.so": "086ec1d5388f64153d9c63470d126693db9a182c8ce236d3a1119068471b8a0d",
        }
        metadata = {
            "needed": ["libc.so.6"],
            "search": ["$ORIGIN"],
            "search_tags": ["DT_RUNPATH"],
        }
        aliases = {"libonnxruntime.so.1": "libonnxruntime.so.1.28.1"}
        self.assertTrue(allow_pinned_ort_origin(path, metadata, digest, files, aliases))
        self.assertFalse(
            allow_pinned_ort_origin(path, metadata, "0" * 64, files, aliases)
        )
        self.assertFalse(
            allow_pinned_ort_origin("/other/ort.so", metadata, digest, files, aliases)
        )
        self.assertFalse(
            allow_pinned_ort_origin(
                path, dict(metadata, search_tags=["DT_RPATH"]), digest, files, aliases
            )
        )
        self.assertFalse(
            allow_pinned_ort_origin(
                path, metadata, digest, dict(files, **{"libc.so.6": "x"}), aliases
            )
        )
        self.assertFalse(allow_pinned_ort_origin(path, metadata, digest, files, {}))
        self.assertFalse(
            allow_pinned_ort_origin(
                path, metadata, digest, files, {"libonnxruntime.so.1": "/other/runtime"}
            )
        )

    def test_dlopen_seed_only_ambiguity_is_rejected(self):
        seeds = [{"lookup": "libze_loader.so.1", "canonical": "/approved/loader"}]
        with self.assertRaises(ValueError):
            resolve_seeds(
                seeds, {"libze_loader.so.1": ["/approved/loader", "/other/loader"]}, str
            )

    def test_dlopen_seed_must_resolve_to_the_declared_endpoint(self):
        seeds = [{"lookup": "libze_loader.so.1", "canonical": "/approved/loader"}]
        self.assertEqual(
            resolve_seeds(seeds, {"libze_loader.so.1": ["/approved/loader"]}, str),
            ["/approved/loader"],
        )
        with self.assertRaises(ValueError):
            resolve_seeds(seeds, {"libze_loader.so.1": ["/other/loader"]}, str)

    def test_loader_overrides_and_unknown_environment_are_refused(self):
        base = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "HOME": "/",
            "IRLUME_NPU_AA_CASE": "bin-native",
            "ORT_DYLIB_PATH": "/opt/irlume/onnxruntime/lib/libonnxruntime.so.1.28.1",
        }
        validate_environment(base)
        for key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "GLIBC_TUNABLES", "UNKNOWN"):
            with self.assertRaises(ValueError):
                validate_environment(dict(base, **{key: ""}))
        with self.assertRaises(ValueError):
            validate_environment(dict(base, IRLUME_NPU_AA_CASE="other"))

    def test_symlink_cannot_escape_approved_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            allowed = root / "allowed"
            allowed.mkdir()
            outside = root / "outside"
            outside.write_bytes(b"not trusted")
            (allowed / "link").symlink_to(outside)
            with self.assertRaises(ValueError):
                trusted_path(allowed / "link", [allowed], os.getuid(), anchor=root)

    def test_writable_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / "library"
            file.write_bytes(b"bad")
            file.chmod(0o666)
            with self.assertRaises(ValueError):
                trusted_path(file, [root], os.getuid(), anchor=root)

    def test_trusted_regular_file_and_alias_are_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "library"
            target.write_bytes(b"known")
            alias = root / "alias"
            alias.symlink_to("library")
            self.assertEqual(
                trusted_path(alias, [root], os.getuid(), anchor=root), target
            )

    def test_missing_or_ambiguous_dependency_is_rejected(self):
        nodes = {"root": {"needed": ["libx.so"], "search": []}}
        for cache in ({}, {"libx.so": ["one", "two"]}):
            with self.assertRaises(ValueError):
                resolve_closure(["root"], cache, nodes.__getitem__)

    def test_dependency_search_path_is_checked_on_every_member(self):
        nodes = {
            "root": {"needed": ["libx.so"], "search": []},
            "one": {"needed": [], "search": ["/unreviewed"]},
        }
        with self.assertRaises(ValueError):
            resolve_closure(["root"], {"libx.so": ["one"]}, nodes.__getitem__)

    def test_complete_graph_terminates_on_cycles(self):
        nodes = {
            "root": {"needed": ["libx.so"], "search": []},
            "one": {"needed": ["libx.so"], "search": []},
        }
        self.assertEqual(
            resolve_closure(["root"], {"libx.so": ["one"]}, nodes.__getitem__), nodes
        )

    def test_parser_reads_real_elf_without_executing_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "example.c"
            source.write_text("int main(void) { return 42; }\n")
            binary = root / "example"
            subprocess.run(
                ["cc", str(source), "-Wl,-rpath,/unreviewed", "-o", str(binary)],
                check=True,
            )
            result = elf_metadata(binary)
            self.assertIn("/unreviewed", result["search"])
            self.assertIn("libc.so.6", result["needed"])
            self.assertTrue(result["interpreter"].startswith("/"))


if __name__ == "__main__":
    unittest.main()

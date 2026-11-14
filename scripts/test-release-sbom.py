#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""SBOM graph regressions, isolated release generation and tracked refresh."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from release_sbom import clean_purl, normalize_sbom, validate_sbom

SPEC = importlib.util.spec_from_file_location("generator", Path(__file__).with_name("generate-release-sbom.py"))
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)

REFRESH_SPEC = importlib.util.spec_from_file_location(
    "refresh", Path(__file__).with_name("refresh-tracked-sboms.py"))
REFRESH = importlib.util.module_from_spec(REFRESH_SPEC)
REFRESH_SPEC.loader.exec_module(REFRESH)


def cargo_bom(prefix="/private/build one"):
    app = f"path+file://{prefix}/crates/irlume-cli#0.14.0"
    dep = f"path+file://{prefix}/other-directory#irlume-common@0.14.0"
    target = app + " bin-target-0"
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.3",
        "metadata": {"component": {
            "name": "irlume-cli", "version": "0.14.0", "bom-ref": app,
            "purl": "pkg:cargo/irlume-cli@0.14.0?download_url=file://.",
            "components": [{"name": "irlume", "version": "0.14.0", "bom-ref": target,
                            "purl": "pkg:cargo/irlume-cli@0.14.0?download_url=file://.#src/main.rs"}],
        }},
        "components": [
            {"name": "irlume-common", "version": "0.14.0", "bom-ref": dep,
             "purl": "pkg:cargo/irlume-common@0.14.0?download_url=file%3A%2F%2F..%2Fother-directory"},
            {"name": "remote", "version": "1", "bom-ref": "remote@1",
             "purl": "pkg:cargo/remote@1?vcs_url=git%2Bhttps://example.invalid/repo%40abc"},
        ],
        "dependencies": [
            {"ref": app, "dependsOn": [dep, "remote@1"]},
            {"ref": target, "dependsOn": [dep]},
            {"ref": dep, "dependsOn": []},
            {"ref": "remote@1", "dependsOn": []},
        ],
    }


class GraphTests(unittest.TestCase):
    def test_real_cargo_shapes_preserve_identity_targets_and_edges(self):
        raw = cargo_bom()
        before = copy.deepcopy(raw)
        doc = normalize_sbom(raw)
        self.assertEqual(raw, before)
        self.assertEqual(doc["metadata"]["component"]["bom-ref"], "pkg:cargo/irlume-cli@0.14.0")
        self.assertEqual(doc["metadata"]["component"]["components"][0]["bom-ref"],
                         "pkg:cargo/irlume-cli@0.14.0#src/main.rs")
        self.assertEqual(doc["dependencies"][0]["dependsOn"], ["pkg:cargo/irlume-common@0.14.0", "remote@1"])
        self.assertEqual(doc["components"][1], raw["components"][1])
        self.assertEqual(doc, normalize_sbom(cargo_bom("/a/completely/different checkout")))
        self.assertEqual(doc, normalize_sbom(doc))
        validate_sbom(doc)

    def test_purl_keeps_remote_qualifiers_and_subpath(self):
        result = clean_purl("pkg:cargo/demo@1?download_url=file%3A%2F%2Ftmp&vcs_url=https%3A%2F%2Fexample.invalid%2Frepo#src/lib.rs")
        self.assertEqual(result, "pkg:cargo/demo@1?vcs_url=https%3A%2F%2Fexample.invalid%2Frepo#src/lib.rs")

    def test_unknown_local_component_has_no_lossy_fallback(self):
        raw = cargo_bom()
        del raw["components"][0]["purl"]
        with self.assertRaisesRegex(ValueError, "no package URL"):
            normalize_sbom(raw)

    def test_colliding_normalized_identities_are_refused(self):
        raw = cargo_bom()
        raw["components"][0]["purl"] = raw["metadata"]["component"]["purl"]
        with self.assertRaisesRegex(ValueError, "duplicate bom-ref"):
            normalize_sbom(raw)

    def test_duplicate_input_identifiers_are_refused(self):
        raw = cargo_bom()
        raw["components"].append(copy.deepcopy(raw["components"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate input bom-ref"):
            normalize_sbom(raw)

    def test_undefined_dependency_parent_and_child_are_refused(self):
        for field in ("ref", "dependsOn"):
            with self.subTest(field=field):
                doc = normalize_sbom(cargo_bom())
                doc["dependencies"][0][field] = "missing" if field == "ref" else ["missing"]
                with self.assertRaisesRegex(ValueError, "undefined"):
                    validate_sbom(doc)

    def test_duplicate_dependency_record_is_refused(self):
        doc = normalize_sbom(cargo_bom())
        doc["dependencies"].append(copy.deepcopy(doc["dependencies"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate dependency entry"):
            validate_sbom(doc)

    def test_malformed_graph_types_raise_actionable_errors(self):
        for field, value in (("components", {}), ("components", [None]),
                             ("dependencies", {}), ("dependencies", [None]),
                             ("dependencies", [{"ref": []}]),
                             ("dependencies", [{"ref": "pkg:cargo/irlume-cli@0.14.0", "dependsOn": "bad"}])):
            with self.subTest(field=field, value=value):
                doc = normalize_sbom(cargo_bom())
                doc[field] = value
                with self.assertRaises(ValueError):
                    validate_sbom(doc)

    def test_encoded_filesystem_urls_are_refused_without_rejecting_prose(self):
        doc = normalize_sbom(cargo_bom())
        doc["metadata"]["component"]["description"] = "profile: production"
        validate_sbom(doc)
        doc["components"][1]["purl"] += "&download_url=file%3A%2F%2Fprivate%2Fbuild"
        with self.assertRaisesRegex(ValueError, "local filesystem"):
            validate_sbom(doc)

    def test_local_vcs_qualifiers_are_refused_instead_of_discarded(self):
        for source in ("git+file:///private/repo", "git%2Bfile%3A%2F%2Fprivate%2Frepo",
                       "hg+file:///private/repo", "custom+git+file:///private/repo"):
            with self.subTest(source=source):
                doc = normalize_sbom(cargo_bom())
                doc["components"][1]["purl"] = "pkg:cargo/remote@1?vcs_url=" + source
                for operation in (validate_sbom, normalize_sbom):
                    with self.assertRaisesRegex(ValueError, "local filesystem"):
                        operation(doc)

    def test_opaque_native_components_and_nested_services_are_valid(self):
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.3",
               "components": [{"bom-ref": "native", "name": "qt"}],
               "services": [{"bom-ref": "service", "services": [{"bom-ref": "child"}]}],
               "dependencies": [{"ref": "service", "dependsOn": ["native", "child"]}]}
        validate_sbom(doc)
        self.assertEqual(len(doc["dependencies"]), 1)


class GenerationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="irlume-sbom-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "source checkout"
        self.repo.mkdir()
        self.out = self.root / "caller output"
        self.repo.joinpath("Cargo.toml").write_text('[workspace.package]\nversion = "99.0.0"\n')
        self.repo.joinpath("Cargo.lock").write_text("# fixture lock\nversion = 4\n")
        self.repo.joinpath("tracked.cdx.json").write_text("preserve this tracked file\n")
        environment = dict(os.environ, HOME=str(self.root), GIT_CONFIG_NOSYSTEM="1",
                           GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                           GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        for command in (("git", "init"), ("git", "add", "."), ("git", "commit", "-m", "fixture")):
            subprocess.run(command, cwd=self.repo, env=environment, check=True, capture_output=True)
        self.before = {p.name: p.read_bytes() for p in self.repo.iterdir() if p.is_file()}
        self.tools = self.root / "tools"
        self.tools.mkdir()
        tool = self.tools / "cargo"
        tool.write_text(f"#!{sys.executable}\n" + r'''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as stream:
    stream.write(json.dumps({"args": args, "cwd": str(pathlib.Path.cwd())}) + "\n")
if args == ["cyclonedx", "--version"]:
    print("cargo-cyclonedx 0.5.9")
elif args[0] == "metadata":
    assert "--locked" in args
elif args[0] == "cyclonedx":
    stage = pathlib.Path.cwd()
    assert not (stage / ".git").exists()
    if os.environ.get("DRIFT"):
        (stage / "Cargo.lock").write_text("changed dependency graph")
    for short in ("cli", "daemon", "pam", "pam-view", "kwallet-init", "gkr-unlock", "password-verify"):
        crate = "irlume-" + short
        ref = f"path+file://{stage}/crates/{crate}#99.0.0"
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.3",
               "metadata": {"component": {"name": crate, "version": "99.0.0",
                   "bom-ref": ref, "purl": f"pkg:cargo/{crate}@99.0.0?download_url=file://."}},
               "components": [], "dependencies": [{"ref": ref, "dependsOn": []}]}
        if os.environ.get("BAD_LAST") and short == "password-verify":
            doc["dependencies"][0]["dependsOn"] = ["missing"]
        path = stage / "crates" / crate / (crate + ".cdx.json")
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(doc))
else:
    raise SystemExit("unexpected cargo command")
''')
        tool.chmod(0o755)
        self.calls = self.root / "calls.jsonl"
        self.environment = {"PATH": str(self.tools) + os.pathsep + os.environ["PATH"], "CALLS": str(self.calls)}

    def generate(self, **environment):
        with patch.dict(os.environ, {**self.environment, **environment}):
            GENERATOR.generate(self.repo, "HEAD", "99.0.0", self.out)

    def test_one_workspace_invocation_isolated_from_source_and_caller_output(self):
        self.generate()
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        generations = [call for call in calls if call["args"][0] == "cyclonedx" and "--version" not in call["args"]]
        self.assertEqual(len(generations), 1)
        self.assertNotEqual(generations[0]["cwd"], str(self.repo))
        self.assertEqual(sorted(path.name for path in self.out.glob("*.cdx.json")),
                         sorted(f"irlume-99.0.0-sbom-{short}.cdx.json" for short in GENERATOR.CRATES))
        self.assertEqual(self.before, {p.name: p.read_bytes() for p in self.repo.iterdir() if p.is_file()})
        self.assertFalse(subprocess.check_output(["git", "status", "--porcelain"], cwd=self.repo).strip())
        for path in self.out.glob("*.json"):
            validate_sbom(json.loads(path.read_text()))

    def test_lockfile_drift_leaves_checkout_and_output_untouched(self):
        with self.assertRaisesRegex(ValueError, "changed the release lockfile"):
            self.generate(DRIFT="1")
        self.assertFalse(self.out.exists())
        self.assertEqual(self.repo.joinpath("Cargo.lock").read_bytes(), self.before["Cargo.lock"])

    def test_last_invalid_document_cannot_emit_a_partial_set(self):
        with self.assertRaisesRegex(ValueError, "undefined dependsOn"):
            self.generate(BAD_LAST="1")
        self.assertFalse(self.out.exists())

    def test_version_mismatch_is_refused_before_running_cargo(self):
        with patch.dict(os.environ, self.environment):
            with self.assertRaisesRegex(ValueError, "source version"):
                GENERATOR.generate(self.repo, "HEAD", "98.0.0", self.out)
        self.assertFalse(self.calls.exists())

    def test_archive_links_and_parent_paths_are_refused(self):
        for name, kind in (("../outside", tarfile.REGTYPE), ("link", tarfile.SYMTYPE),
                           ("hardlink", tarfile.LNKTYPE)):
            with self.subTest(name=name):
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode="w") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/outside"
                    archive.addfile(member)
                data.seek(0)
                with tarfile.open(fileobj=data) as archive:
                    with self.assertRaises(ValueError):
                        GENERATOR.extract_source(archive, self.root)


class TrackedRefreshTests(unittest.TestCase):
    """Regeneration of the committed crates/*/irlume-*.cdx.json documents."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="irlume-sbom-tracked-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "tracked checkout"
        self.root.mkdir()
        self.lock_text = "# fixture lock\nversion = 4\n"
        self.root.joinpath("Cargo.toml").write_text('[workspace.package]\nversion = "99.0.0"\n')
        self.root.joinpath("Cargo.lock").write_text(self.lock_text)
        document = self.root / "crates" / "irlume-demo" / "irlume-demo.cdx.json"
        document.parent.mkdir(parents=True)
        document.write_text(json.dumps(self.document("irlume-demo", "98.0.0", "/stale/checkout")))
        environment = dict(os.environ, HOME=str(self.temp.name), GIT_CONFIG_NOSYSTEM="1",
                           GIT_AUTHOR_NAME="Fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                           GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        for command in (("git", "init"), ("git", "add", "."), ("git", "commit", "-m", "fixture")):
            subprocess.run(command, cwd=self.root, env=environment, check=True, capture_output=True)
        self.stale = document.read_bytes()
        self.tools = self.root.parent / "tools"
        self.tools.mkdir()
        tool = self.tools / "cargo"
        tool.write_text(f"#!{sys.executable}\n" + r'''
import json, os, pathlib, sys
args = sys.argv[1:]
if args == ["cyclonedx", "--version"]:
    print(os.environ.get("TOOL_VERSION", "cargo-cyclonedx 0.5.9"))
elif args and args[0] == "metadata":
    # cargo metadata --locked refuses a lockfile the manifest disagrees
    # with before any generation runs; DRIFT simulates that refusal.
    sys.exit(1 if os.environ.get("DRIFT") else 0)
else:
    assert args[0] == "cyclonedx" and "--format" in args and "--spec-version" in args
    root = pathlib.Path(args[args.index("--manifest-path") + 1]).parent
    if os.environ.get("DRIFT_AFTER"):
        (root / "Cargo.lock").write_text("changed dependency graph")
    members = ["irlume-demo"] + os.environ.get("EXTRA_MEMBER", "").split()
    for crate in members:
        name = "irlume-stranger" if os.environ.get("WRONG_NAME") and crate == "irlume-demo" else crate
        ref = f"path+file://{root}/crates/{crate}#99.0.0"
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.3",
               "metadata": {"component": {"name": name, "version": "99.0.0",
                   "bom-ref": ref, "purl": f"pkg:cargo/{name}@99.0.0?download_url=file://."}},
               "components": [], "dependencies": [{"ref": ref, "dependsOn": []}]}
        path = root / "crates" / crate / (crate + ".cdx.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc))
''')
        tool.chmod(0o755)
        self.environment = {"PATH": str(self.tools) + os.pathsep + os.environ["PATH"]}

    def document(self, crate, version, checkout):
        ref = f"path+file://{checkout}/crates/{crate}#{version}"
        return {"bomFormat": "CycloneDX", "specVersion": "1.3",
                "metadata": {"component": {"name": crate, "version": version,
                    "bom-ref": ref,
                    "purl": f"pkg:cargo/{crate}@{version}?download_url=file://."}},
                "components": [], "dependencies": [{"ref": ref, "dependsOn": []}]}

    def test_tracked_documents_are_renormalized_and_untracked_extras_removed(self):
        with patch.dict(os.environ, {**self.environment, "EXTRA_MEMBER": "irlume-extra"}):
            REFRESH.refresh(self.root)
        path = self.root / "crates" / "irlume-demo" / "irlume-demo.cdx.json"
        text = path.read_text()
        self.assertTrue(text.endswith("\n"))
        document = json.loads(text)
        component = document["metadata"]["component"]
        self.assertEqual((component["name"], component["version"]), ("irlume-demo", "99.0.0"))
        self.assertEqual(component["bom-ref"], "pkg:cargo/irlume-demo@99.0.0")
        self.assertEqual(component["purl"], "pkg:cargo/irlume-demo@99.0.0")
        validate_sbom(document)
        self.assertFalse((self.root / "crates" / "irlume-extra" / "irlume-extra.cdx.json").exists())
        self.assertEqual(self.root.joinpath("Cargo.lock").read_text(), self.lock_text)
        status = subprocess.check_output(["git", "status", "--porcelain"],
                                         cwd=self.root, text=True)
        self.assertEqual(status.splitlines(), [" M crates/irlume-demo/irlume-demo.cdx.json"])

    def test_unpinned_tool_version_is_refused_without_touching_the_tree(self):
        with patch.dict(os.environ, {**self.environment, "TOOL_VERSION": "cargo-cyclonedx 0.6.0"}):
            with self.assertRaisesRegex(ValueError, "need cargo-cyclonedx 0.5.9"):
                REFRESH.refresh(self.root)
        path = self.root / "crates" / "irlume-demo" / "irlume-demo.cdx.json"
        self.assertEqual(path.read_bytes(), self.stale)

    def test_lockfile_drift_is_refused_before_anything_is_touched(self):
        with patch.dict(os.environ, {**self.environment, "DRIFT": "1"}):
            with self.assertRaises(subprocess.CalledProcessError):
                REFRESH.refresh(self.root)
        self.assertEqual(self.root.joinpath("Cargo.lock").read_text(), self.lock_text)
        path = self.root / "crates" / "irlume-demo" / "irlume-demo.cdx.json"
        self.assertEqual(path.read_bytes(), self.stale)

    def test_a_lock_change_during_generation_is_refused(self):
        with patch.dict(os.environ, {**self.environment, "DRIFT_AFTER": "1"}):
            with self.assertRaisesRegex(ValueError, "changed Cargo.lock"):
                REFRESH.refresh(self.root)
        self.assertEqual(self.root.joinpath("Cargo.lock").read_text(), "changed dependency graph")

    def test_foreign_component_identity_is_refused(self):
        with patch.dict(os.environ, {**self.environment, "WRONG_NAME": "1"}):
            with self.assertRaisesRegex(ValueError, "unexpected SBOM component identity"):
                REFRESH.refresh(self.root)

    def test_repository_without_tracked_documents_is_refused(self):
        (self.root / "crates" / "irlume-demo" / "irlume-demo.cdx.json").unlink()
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True, capture_output=True)
        with patch.dict(os.environ, self.environment):
            with self.assertRaisesRegex(ValueError, "no tracked SBOM documents"):
                REFRESH.refresh(self.root)


class ShippedArtifactCoverage(unittest.TestCase):
    """docs/RELEASING.md: one SBOM per crate that builds a shipped binary."""

    # The Rust artifacts the packaging recipes install, and the crate each is
    # built from. A recipe that installs another artifact fails here until the
    # artifact is listed and its crate has an SBOM.
    ARTIFACT_CRATE = {
        "irlume": "cli",
        "irlumed": "daemon",
        "libpam_irlume.so": "pam",
        "libpam_irlume_view.so": "pam-view",
        "irlume-kwallet-init": "kwallet-init",
        "irlume-gkr-unlock": "gkr-unlock",
        "irlume-password-verify": "password-verify",
    }
    RECIPES = ("packaging/arch/PKGBUILD", "packaging/arch-git/PKGBUILD",
               "packaging/debian/nfpm.yaml", "packaging/fedora/irlume.spec",
               "packaging/ppa/debian/rules")

    def test_every_installed_rust_artifact_has_an_sbom_crate(self):
        root = Path(__file__).resolve().parent.parent
        for recipe in self.RECIPES:
            with self.subTest(recipe=recipe):
                installed = set(re.findall(r"target/release/([A-Za-z0-9_.-]+)",
                                           (root / recipe).read_text()))
                self.assertEqual(installed, set(self.ARTIFACT_CRATE))
        self.assertEqual(sorted(self.ARTIFACT_CRATE.values()), sorted(GENERATOR.CRATES))
        for short in GENERATOR.CRATES:
            self.assertTrue((root / "crates" / f"irlume-{short}" / "Cargo.toml").is_file(), short)


if __name__ == "__main__":
    unittest.main()

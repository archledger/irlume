# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Local-reference normalization and graph checks for release CycloneDX SBOMs.

These are release graph-integrity checks, not a full JSON Schema validator.
Dependencies absent from the graph remain opaque; no edges are invented.
"""
import copy
import re
from urllib.parse import parse_qsl, unquote, urlencode


def objects(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from objects(value)
    elif isinstance(node, list):
        for value in node:
            yield from objects(value)


def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)


def local_reference(value):
    return re.search(r"(?<![A-Za-z0-9_+.-])(?:[A-Za-z][A-Za-z0-9+.-]*\+)?file:",
                     unquote(value), re.IGNORECASE) is not None


def clean_purl(value):
    if not isinstance(value, str) or not value.startswith("pkg:"):
        raise ValueError("local component has no package URL")
    head, separator, fragment = value.partition("#")
    base, _, query = head.partition("?")
    qualifiers = parse_qsl(query, keep_blank_values=True)
    retained = [(key, item) for key, item in qualifiers
                if not (key == "download_url" and local_reference(item))]
    if retained == qualifiers:
        return value
    return base + ("?" + urlencode(retained) if retained else "") + separator + fragment


def validate_sbom(doc):
    """Reject ambiguous identifiers, dangling edges and local filesystem URLs."""
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise ValueError("missing CycloneDX bomFormat")
    for node in objects(doc):
        for key in ("components", "services"):
            if key in node and (not isinstance(node[key], list)
                                or any(not isinstance(item, dict) for item in node[key])):
                raise ValueError(f"{key} must be an array of objects")
    definitions = set()
    for node in objects(doc):
        if "bom-ref" not in node:
            continue
        ref = node["bom-ref"]
        if not isinstance(ref, str) or not ref:
            raise ValueError("bom-ref must be a nonempty string")
        if ref in definitions:
            raise ValueError(f"duplicate bom-ref: {ref}")
        definitions.add(ref)
    dependencies = doc.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("dependencies must be an array")
    parents = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("dependency must be an object")
        ref = dependency.get("ref")
        if not isinstance(ref, str) or ref not in definitions:
            raise ValueError(f"undefined dependency ref: {ref!r}")
        if ref in parents:
            raise ValueError(f"duplicate dependency entry: {ref}")
        parents.add(ref)
        children = dependency.get("dependsOn", [])
        if not isinstance(children, list):
            raise ValueError("dependsOn must be an array")
        for child in children:
            if not isinstance(child, str) or child not in definitions:
                raise ValueError(f"undefined dependsOn ref: {child!r}")
    if any(local_reference(value) for value in strings(doc)):
        raise ValueError("local filesystem reference in SBOM")


def normalize_sbom(original):
    """Rewrite identities and edges together using each component's own purl.

    cargo-cyclonedx puts target source subpaths in nested-component purls.
    Keeping them distinguishes a crate from its binary targets without parsing
    Cargo's version-dependent path package-ID spelling.
    """
    doc = copy.deepcopy(original)
    mapping = {}
    seen = set()
    for node in objects(doc):
        if "purl" in node:
            node["purl"] = clean_purl(node["purl"])
        if "bom-ref" not in node:
            continue
        ref = node["bom-ref"]
        if not isinstance(ref, str) or not ref:
            raise ValueError("bom-ref must be a nonempty string")
        if ref in seen:
            raise ValueError(f"duplicate input bom-ref: {ref}")
        seen.add(ref)
        if local_reference(ref):
            mapping[ref] = clean_purl(node.get("purl"))

    def rewrite(node):
        if isinstance(node, str):
            return mapping.get(node, node)
        if isinstance(node, list):
            return [rewrite(value) for value in node]
        if isinstance(node, dict):
            return {key: rewrite(value) for key, value in node.items()}
        return node

    doc = rewrite(doc)
    validate_sbom(doc)
    return doc

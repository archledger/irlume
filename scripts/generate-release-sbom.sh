#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Generate the CycloneDX SBOM set for an irlume release. One SBOM per crate
# that builds a binary shipped in the release packages; each is version-named
# for upload as a release asset and coverage in the signed SHA256SUMS.
#
#   scripts/generate-release-sbom.sh 0.13.0 [output-dir]
#
# Requires cargo-cyclonedx (cargo install cargo-cyclonedx --locked) and the
# release tag checked out, so dependency resolution matches what shipped.
set -euo pipefail

VERSION="${1:?usage: generate-release-sbom.sh VERSION [output-dir]}"
OUT="${2:-.}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

command -v cargo-cyclonedx >/dev/null || { echo "need cargo-cyclonedx" >&2; exit 2; }

# Crates whose binaries ship in the release packages (PKGBUILD is the
# source of truth for that list).
CRATES=(irlume-cli irlume-daemon irlume-pam irlume-kwallet-init irlume-gkr-unlock irlume-password-verify)

# cargo-cyclonedx embeds the generator's absolute source paths as
# path+file:///... bom-refs and file:// download URLs. Those leak the build
# machine's filesystem and make two runs on different hosts differ, so every
# local path reference is rewritten to the canonical crates.io identity
# before the asset is considered release-ready. The purl is untouched.
normalize() {
  python3 - "$1" <<'PYEOF'
import json, sys, re

path = sys.argv[1]
doc = json.load(open(path, encoding="utf-8"))

def canonical_ref(ref):
    if not isinstance(ref, str) or not ref.startswith("path+file:"):
        return ref
    tail = ref.split("file://", 1)[-1]           # /home/x/irlume/crates/foo
    m = re.search(r"crates/([A-Za-z0-9_-]+)/?$", tail)
    return f"pkg:cargo/{m.group(1)}" if m else "urn:irlume:local-source"

def walk(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("bom-ref", "ref") :
                node[key] = canonical_ref(value)
            elif key == "download_url" and isinstance(value, str) and value.startswith("file://"):
                node[key] = None
            elif key == "purl" and isinstance(value, str) and value.startswith("pkg:cargo/"):
                pass
            else:
                walk(value)
    elif isinstance(node, list):
        for item in node:
            walk(item)

walk(doc)
json.dump(doc, open(path, "w", encoding="utf-8"), indent=2)
PYEOF
}

cd "$REPO"
for crate in "${CRATES[@]}"; do
  cargo cyclonedx --manifest-path "crates/$crate/Cargo.toml" -f json >/dev/null
  src="crates/$crate/$crate.cdx.json"
  short="${crate#irlume-}"
  dst="$OUT/irlume-${VERSION}-sbom-${short}.cdx.json"
  mv "$src" "$dst"
  normalize "$dst"
  count=$(python3 - "$dst" <<'PYEOF'
import json, sys
print(len(json.load(open(sys.argv[1], encoding="utf-8")).get("components", [])))
PYEOF
)
  echo "wrote $dst ($count components)"
done

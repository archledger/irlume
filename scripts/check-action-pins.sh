#!/usr/bin/env bash
# Enforce SHA-pinning of every GitHub Action `uses:` reference, with ONE
# documented, scoped exception: the SLSA provenance generator.
#
# Why this exists instead of GitHub's native "require actions pinned to a
# full-length commit SHA" repo setting: that setting applies to ALL actions
# with no exception mechanism (confirmed against GitHub docs 2026-07), and it
# rejects the slsa-github-generator, whose own L3 security model requires its
# internal actions to be referenced by tag so a release can attest to a known,
# verifiable version. This script keeps the guarantee (nothing else may use a
# mutable tag/branch ref) while allowing exactly that one generator, which the
# native toggle cannot express. Runs in CI on every push and PR.
set -euo pipefail

# The single allowed non-SHA reference: the SLSA generator reusable workflow.
# It is version-pinned by tag (@vX.Y.Z) by design and is itself provenanced.
ALLOW_TAG_PREFIX="slsa-framework/slsa-github-generator/"

fail=0
while IFS= read -r line; do
  file="${line%%:*}"
  rest="${line#*:}"
  # The reference is the token after `uses:` (strip a leading `- `).
  ref="$(printf '%s' "$rest" | sed -E 's/.*uses:[[:space:]]*//; s/[[:space:]]+#.*//; s/[[:space:]]*$//')"
  [ -z "$ref" ] && continue
  # Local actions (./path) carry no external supply-chain risk.
  case "$ref" in
    ./*) continue ;;
    "$ALLOW_TAG_PREFIX"*) continue ;;
  esac
  # Everything else must be owner/repo(/path)@<40-hex-sha>.
  if ! printf '%s' "$ref" | grep -Eq '@[0-9a-f]{40}$'; then
    echo "NOT SHA-PINNED: $file -> $ref"
    fail=1
  fi
done < <(grep -rnE '^[[:space:]]*(-[[:space:]]+)?uses:' .github/workflows/)

if [ "$fail" -ne 0 ]; then
  echo
  echo "All actions must be pinned to a full-length commit SHA."
  echo "The only allowed tag reference is ${ALLOW_TAG_PREFIX}* (SLSA generator)."
  exit 1
fi
echo "All action references are SHA-pinned (SLSA generator excepted)."

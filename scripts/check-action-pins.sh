#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Enforce SHA-pinning of every GitHub Action `uses:` reference. There are no
# exceptions, first-party or third-party.
#
# Why this exists instead of GitHub's native "require actions pinned to a
# full-length commit SHA" repo setting: that setting applies to ALL actions
# with no exception mechanism (confirmed against GitHub docs 2026-07). While
# the SLSA provenance generator was in use, this script carved out exactly one
# tag-referenced exception, because the generator's own L3 security model
# requires its reusable workflow to be referenced by an @vX.Y.Z tag; the
# release workflow now attests with GitHub artifact attestations instead, so
# every reference is SHA-pinned and the exception is retired. The script stays
# because it runs on every push and PR and names each offending reference.
set -euo pipefail

# Discovery has to be counted and its status checked, not assumed. Reading the
# matches from a process substitution hid both: `while ... done < <(grep ...)`
# runs the loop zero times when grep matches nothing, and a process
# substitution's exit status is invisible to `set -e` and pipefail, so the
# script printed success having examined no references at all. That is reachable
# without anyone touching this file: reformatting to `uses :`, moving steps into
# generated YAML, or a rename of the workflows directory all produce it.
#
# grep is therefore run as its own command whose status is inspected: 0 is
# matches, 1 is a clean no-match, and anything above that is a read error, which
# means an unknown share of the workflows went unexamined.
refs="$(mktemp)"
trap 'rm -f "$refs"' EXIT

grep_status=0
grep -rnE '^[[:space:]]*(-[[:space:]]+)?uses:' .github/workflows/ > "$refs" || grep_status=$?

if [ "$grep_status" -gt 1 ]; then
  echo "Search over .github/workflows/ failed (grep exited $grep_status)."
  echo "Some workflows were not read, so nothing here can be called pinned."
  exit 1
fi

seen=0
fail=0
while IFS= read -r line; do
  seen=$((seen + 1))
  file="${line%%:*}"
  rest="${line#*:}"
  # The reference is the token after `uses:` (strip a leading `- `).
  ref="$(printf '%s' "$rest" | sed -E 's/.*uses:[[:space:]]*//; s/[[:space:]]+#.*//; s/[[:space:]]*$//')"
  [ -z "$ref" ] && continue
  # Local actions (./path) carry no external supply-chain risk.
  case "$ref" in
    ./*) continue ;;
  esac
  # Everything else must be owner/repo(/path)@<40-hex-sha>.
  if ! printf '%s' "$ref" | grep -Eq '@[0-9a-f]{40}$'; then
    echo "NOT SHA-PINNED: $file -> $ref"
    fail=1
  fi
done < "$refs"

if [ "$seen" -eq 0 ]; then
  echo "No 'uses:' references found under .github/workflows/."
  echo "Every workflow here uses at least one action, so finding none means the"
  echo "search stopped matching, not that the repository stopped using actions."
  exit 1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "All actions must be pinned to a full-length commit SHA."
  exit 1
fi
echo "All $seen action references are SHA-pinned."

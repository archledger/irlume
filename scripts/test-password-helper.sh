#!/usr/bin/env bash
# Exercise actual libpam using only private synthetic fixtures, never host PAM.
set -euo pipefail
cd "$(dirname "$0")/.."
test_binary="$(cargo test -p irlume-password-verify --locked --test pam --no-run --message-format=json | python3 -c '
import json, sys
paths = [row["executable"] for row in map(json.loads, sys.stdin)
         if row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == "pam" and row.get("executable")]
assert len(paths) == 1, paths
print(paths[0])
')"
./scripts/run-tests-guarded.sh --min 1 -- "$test_binary" unprivileged_invocation_is_unavailable --exact
./scripts/run-tests-guarded.sh --min 1 -- sudo -n setpriv --no-new-privs --bounding-set=-all,+dac_override,+fowner "$test_binary" actual_pam_contract --exact --ignored --nocapture

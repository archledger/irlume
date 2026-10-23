#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# These in-memory checks provide no launch permission or native loading.
set -euo pipefail
cd "$(dirname -- "$0")/.."
export RUSTFLAGS='--cfg irlume_hw_evidence'
export RUSTDOCFLAGS='--cfg irlume_hw_evidence -D warnings'
scripts/run-tests-guarded.sh --min 15 \
  --require valid_description_is_not_a_launch_capability \
  --require rejects_untrusted_file_observations \
  --require rejects_invalid_environment_description \
  --require rejects_omitted_or_conflicting_roles \
  --require description_requires_exact_observation_and_digest \
  --require rejects_duplicate_and_undeclared_observations \
  --require rejects_invalid_paths_without_lossy_normalization \
  --require rejects_duplicate_declared_paths \
  --require environment_is_exact_and_preserves_absent_empty_and_duplicates \
  --require rejects_invalid_header_and_noncanonical_digests \
  --require rejects_oversized_descriptions_before_member_validation \
  --require bounds_apply_to_names_values_and_paths \
  --require rejects_conflicting_alias_observations \
  --require accepts_matching_alias_observations \
  --require accepts_description_at_maximum_bounds \
  -- cargo test --locked -p irlume-vision --features npu --lib measurement_profile::
scripts/run-tests-guarded.sh --min 2 -- \
  cargo test --locked -p irlume-vision --features npu --doc measurement_profile
cargo clippy --locked -p irlume-vision --features npu --all-targets -- -D warnings
cargo doc --locked -p irlume-vision --features npu --no-deps

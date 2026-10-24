#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Portable policy tests by default; --kernel requires real full-flag support.
set -euo pipefail
cd "$(dirname -- "$0")/.."
[[ $# -le 1 ]] || exit 2
mode=${1:---portable}
export RUSTFLAGS='--cfg irlume_hw_evidence'
export RUSTDOCFLAGS='--cfg irlume_hw_evidence -D warnings'
case "$mode" in
  --portable)
    exec scripts/run-tests-guarded.sh --min 18 \
      --require acquisition_passes_owned_files_to_observer \
      --require acquisition_preserves_original_path_spelling \
      --require acquisition_rejects_invalid_paths_before_open \
      --require acquisition_rejects_duplicate_and_empty_batches \
      --require acquisition_rejects_root_symlink_and_wrong_root \
      --require acquisition_checks_root_at_every_checkpoint \
      --require acquisition_retry_budget_is_batch_wide \
      --require acquisition_never_relaxes_flags_after_errors \
      --require acquisition_open_how_matches_v0_abi \
      --require acquisition_checks_returned_leaf_policy \
      --require acquisition_cleans_partial_files_on_failure \
      --require acquisition_enforces_limits_before_syscalls \
      --require acquisition_observer_refusal_drops_all_fds \
      --require acquisition_errors_are_redacted_and_have_no_authority \
      --require acquisition_rejects_root_alias_spellings \
      --require acquisition_detects_intermediate_directory_replacement \
      --require acquisition_detects_leaf_stamp_changes \
      --require acquisition_closes_root_on_success \
      -- cargo test --locked -p irlume-vision --features npu --lib measurement_profile::acquire:: ;;
  --kernel)
    exec scripts/run-tests-guarded.sh --min 1 \
      --require kernel_acquisition_requires_regular_file_resolution \
      -- cargo test --locked -p irlume-vision --features npu --lib \
      measurement_profile::acquire::tests::kernel_acquisition_requires_regular_file_resolution \
      -- --exact --ignored --nocapture ;;
  *) exit 2 ;;
esac

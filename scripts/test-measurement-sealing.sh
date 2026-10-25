#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Portable fault checks by default; --kernel requires actual memfd seals.
set -euo pipefail
cd "$(dirname -- "$0")/.."
[[ $# -le 1 ]] || exit 2
export RUSTFLAGS='--cfg irlume_hw_evidence'
export RUSTDOCFLAGS='--cfg irlume_hw_evidence -D warnings'
case "${1:---portable}" in
  --portable)
    exec scripts/run-tests-guarded.sh --min 11 \
      --require sealing_refuses_empty_files \
      --require sealing_uses_observed_bytes_not_a_new_source_read \
      --require sealing_refuses_empty_batch_before_creating_files \
      --require sealing_accounts_for_short_and_interrupted_io \
      --require sealing_io_budget_is_batch_wide_and_counts_interruptions \
      --require sealing_checks_each_required_seal_independently \
      --require sealing_refuses_failed_operations_and_mismatched_readbacks \
      --require sealing_debug_output_is_redacted \
      --require sealing_size_limits_include_checked_aggregate_overflow \
      --require sealing_checks_every_byte_across_chunk_and_file_boundaries \
      --require sealing_closes_partial_output_in_isolated_child \
      -- cargo test --locked -p irlume-vision --features npu --lib measurement_profile::seal:: ;;
  --kernel)
    exec scripts/run-tests-guarded.sh --min 1 \
      --require kernel_sealing_keeps_exact_bytes_and_all_required_seals \
      -- cargo test --locked -p irlume-vision --features npu --lib \
      measurement_profile::seal::tests::kernel_sealing_keeps_exact_bytes_and_all_required_seals \
      -- --exact --ignored --nocapture ;;
  *) exit 2 ;;
esac

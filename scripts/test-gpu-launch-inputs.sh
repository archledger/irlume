#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Pure candidate-input checks only; this does not authorize native loading.
set -euo pipefail
cd "$(dirname -- "$0")/.."
exec scripts/run-tests-guarded.sh --min 14 \
  --require minimal_candidate_declares_cache_off_without_authorizing_loading \
  --require optional_locales_accept_only_c_in_every_entry_order \
  --require missing_cache_intent_is_not_inferred_from_optional_locales \
  --require cache_value_requires_exact_ascii_zero_without_normalization \
  --require each_optional_locale_rejects_nonexact_values \
  --require every_other_name_is_unsupported_even_with_an_empty_value \
  --require names_follow_the_exact_ascii_grammar \
  --require duplicate_names_refuse_equal_and_different_values \
  --require bounds_are_raw_bytes_and_include_the_exact_limits \
  --require unknown_policy_wins_over_every_environment_error \
  --require error_precedence_is_independent_of_entry_permutation \
  --require errors_are_fixed_categories_without_raw_name_or_value_payloads \
  --require borrowed_inputs_are_unchanged_and_checked_output_retains_no_input_lifetime \
  --require candidate_checker_has_no_ambient_or_native_operations \
  -- cargo test --locked -p irlume-vision --features npu --lib npu::gpu::launch::

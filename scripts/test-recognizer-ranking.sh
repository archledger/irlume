#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Pure hypothetical recommendations; no discovery, loading or placement.
set -euo pipefail
cd "$(dirname -- "$0")/.."
exec scripts/run-tests-guarded.sh --min 30 \
  --require explicit_cpu_ignores_candidates_keys_and_evidence \
  --require explicit_accelerators_use_matching_assertions_without_ranking_evidence \
  --require explicit_preferences_never_substitute_the_other_accelerator \
  --require explicit_switch_refusal_precedes_candidate_and_scope_validation \
  --require explicit_preferences_preserve_each_asserted_refusal_and_unobserved_state \
  --require explicit_preference_ignores_other_class_assessment_and_evidence \
  --require auto_follows_either_evidence_order_independent_of_candidate_enumeration \
  --require auto_can_recommend_cpu_ahead_of_both_asserted_eligible_accelerators \
  --require independent_switches_filter_hypothetical_assertions_not_runtime_collectors \
  --require auto_skips_refused_and_unobserved_candidates_even_if_ordered_first \
  --require auto_without_eligible_candidates_needs_no_order \
  --require eligible_auto_candidate_without_evidence_does_not_get_a_default_rank \
  --require repeated_enabled_candidates_refuse_identical_and_conflicting_assertions \
  --require repeated_disabled_class_records_are_not_considered \
  --require candidate_records_are_bounded \
  --require orders_are_bounded_and_require_cpu_exactly_once \
  --require duplicate_order_classes_refuse_even_when_the_class_is_ineligible \
  --require missing_eligible_targets_refuse_even_when_cpu_is_first \
  --require unknown_identity_for_an_eligible_class_refuses_instead_of_skipping \
  --require nonempty_unknown_identity_for_an_ineligible_class_may_be_skipped \
  --require candidate_workload_mismatch_refuses_explicit_and_auto_recommendations \
  --require one_matching_candidate_does_not_hide_another_eligible_workload_mismatch \
  --require evidence_workload_must_match_exactly \
  --require empty_requested_or_eligible_candidate_keys_refuse \
  --require empty_evidence_workload_or_order_key_refuses \
  --require disabled_and_unobserved_candidate_keys_are_not_treated_as_evidence \
  --require candidate_key_equality_does_not_trim_fold_case_or_ignore_trailing_bytes \
  --require opaque_binary_keys_are_not_required_to_be_hashes_or_utf8 \
  --require equal_candidate_bytes_do_not_confuse_accelerator_classes \
  --require recommendation_borrows_the_candidate_key_not_the_evidence_key \
  -- cargo test --locked -p irlume-common --lib recognizer_ranking::

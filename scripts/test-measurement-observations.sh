#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Explicit local fixture handles only. No launch or installed runtime access.
set -euo pipefail
cd "$(dirname -- "$0")/.."
export RUSTFLAGS='--cfg irlume_hw_evidence'
export RUSTDOCFLAGS='--cfg irlume_hw_evidence -D warnings'
scripts/run-tests-guarded.sh --min 17 \
  --require accepts_exact_fixture_budget_boundaries \
  --require accepts_matching_symlink_and_hardlink_aliases \
  --require aliases_charge_each_retained_allocation \
  --require final_batch_recheck_rejects_earlier_file_change \
  --require handles_short_reads_and_bounded_eintr \
  --require observer_result_is_non_authorizing_and_debug_is_redacted \
  --require observes_fixture_bytes_and_retains_hash_allocation \
  --require preserves_runtime_trust_and_symlink_refusals \
  --require preserves_supplied_descriptor_cursor \
  --require rejects_changed_metadata_or_endpoint \
  --require rejects_conflicting_alias_snapshots \
  --require rejects_invalid_paths_and_oversized_limits_without_reading \
  --require rejects_nonregular_or_untrusted_descriptors_before_read \
  --require rejects_path_descriptor_identity_mismatch \
  --require rejects_unresolvable_original_path_spelling \
  --require rejects_truncation_growth_and_budget_exhaustion \
  --require reports_reservation_failure_without_partial_result \
  -- cargo test --locked -p irlume-vision --features npu --lib measurement_profile::observe::
scripts/run-tests-guarded.sh --min 18 \
  --require a_bad_explicit_install_never_chooses_another_present_runtime \
  --require a_dangling_standard_root_is_not_absence_and_refuses_lower_candidates \
  --require absent_selection_is_automatic_and_environment_selects_any_provider \
  --require administrator_ownership_is_required_independent_of_provider_name \
  --require alias_hops_cannot_leave_the_trust_boundary_and_return \
  --require an_explicit_reviewed_source_install_and_trusted_alias_resolve \
  --require an_unresolvable_directory_ancestor_is_not_absence_and_refuses \
  --require automatic_lookup_refuses_nonabsence_errors_before_lower_candidates \
  --require cyclic_missing_and_non_directory_alias_paths_are_refused \
  --require directory_alias_chain_is_validated_before_remaining_components \
  --require genuine_absence_still_advances_and_empty_root_list_stays_not_found \
  --require invalid_explicit_values_do_not_turn_into_automatic_discovery \
  --require library_alias_chain_validates_every_absolute_and_relative_hop \
  --require machine_settings_preserve_absence_and_reject_ambiguity_or_unknown_reads \
  --require malformed_exact_library_keys_refuse_automatic_selection \
  --require parent_components_follow_resolved_directory_aliases \
  --require unchanged_legacy_alias_keeps_exact_identity_and_canonical_load_path \
  --require writable_files_or_ancestors_and_untrusted_alias_targets_are_refused \
  -- cargo test --locked -p irlume-vision --features npu --lib npu::runtime::tests::
scripts/run-tests-guarded.sh --min 2 -- \
  cargo test --locked -p irlume-vision --features npu --doc measurement_profile::observe::

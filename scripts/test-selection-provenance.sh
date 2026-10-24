#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
set -euo pipefail
cd "$(dirname -- "$0")/.."
python3 scripts/ci/test-isolated-cli.py
scripts/run-tests-guarded.sh --min 9 \
  --require selection_provenance_known_values_round_trip_as_strings \
  --require selection_provenance_outer_absence_is_not_a_default_selection \
  --require selection_provenance_missing_members_are_unknown_not_default_or_none \
  --require selection_provenance_future_strings_normalize_without_retaining_raw_values \
  --require selection_provenance_wrong_member_types_are_errors \
  --require selection_provenance_wrong_outer_types_are_errors \
  --require selection_provenance_unknown_object_fields_are_forward_compatible \
  --require selection_provenance_new_fields_are_ignored_by_a_legacy_reader \
  --require selection_provenance_explicit_default_is_distinct_from_missing_data \
  -- cargo test --locked -p irlume-common --lib selection_provenance
for mode in default npu; do
  features=()
  if [[ $mode == npu ]]; then features=(--features npu); fi
  scripts/run-tests-guarded.sh --min 5 \
    --require selection_provenance_preserves_existing_source_precedence \
    --require selection_provenance_stamps_one_copied_plan_despite_newer_publication \
    --require selection_provenance_resolution_alone_does_not_publish_replacement_metadata \
    --require selection_provenance_retirement_preserves_intent_and_peer_privacy \
    --require selection_provenance_without_publication_remains_unreported \
    -- cargo test --locked -p irlume-daemon "${features[@]}" --bin irlumed selection_provenance_tests::
done
scripts/run-tests-guarded.sh --min 5 \
  --require selection_provenance_status_omits_unreported_data \
  --require selection_provenance_status_reports_known_and_future_values \
  --require selection_provenance_doctor_distinguishes_default_unknown_and_unreported \
  --require selection_provenance_doctor_issues_do_not_change_existing_severity \
  --require selection_provenance_schema_matches_emitted_strings \
  -- cargo test --locked -p irlume-cli --bin irlume selection_provenance_tests::
scripts/run-tests-guarded.sh --min 1 \
  --require isolated_selection_provenance_real_cli_positive_health_cases \
  -- cargo test --locked -p irlume-cli --test selection_provenance

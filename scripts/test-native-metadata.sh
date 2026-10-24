#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Supplied ELF bytes only; no loader, device discovery or runtime admission.
set -euo pipefail
cd "$(dirname -- "$0")/.."
export RUSTDOCFLAGS='-D warnings'
check_parser() {
  scripts/run-tests-guarded.sh --min 19 \
    --require extracts_program_header_metadata_without_sections \
    --require ignores_conflicting_section_dynamic_metadata \
    --require preserves_raw_strings_unknown_tags_and_loading_notices \
    --require preserves_needed_order_duplicates_and_empty_values \
    --require distinguishes_dynamic_terminator_and_trailing_entries \
    --require rejects_truncation_overflow_and_ambiguous_translation \
    --require rejects_duplicate_singletons_and_unterminated_strings \
    --require enforces_exact_metadata_resource_bounds \
    --require borrows_the_supplied_buffer_without_ambient_access \
    --require metadata_success_does_not_authorize_loading \
    --require unknown_program_headers_and_header_flags_are_reported \
    --require format_and_entry_sizes_fail_explicitly \
    --require exact_input_and_program_header_bounds_are_accepted \
    --require absent_dynamic_and_interpreter_are_distinct_from_empty_strings \
    --require incomplete_dynamic_entries_and_load_overflows_are_refused \
    --require repeated_search_paths_and_post_terminator_singletons_stay_raw \
    --require interpreter_counts_against_string_budget_and_stays_unresolved \
    --require string_table_size_and_offsets_cannot_escape_file_backed_data \
    --require rejects_partial_string_table_load_overlaps \
    -- cargo test --locked -p irlume-vision "$@" --lib native_metadata::
  cargo clippy --locked -p irlume-vision "$@" --all-targets -- -D warnings
}
check_parser --no-default-features --features native-metadata
check_parser --features npu,native-metadata
scripts/run-tests-guarded.sh --min 3 -- \
  cargo test --locked -p irlume-vision --no-default-features --features native-metadata --doc native_metadata
cargo doc --locked -p irlume-vision --no-default-features --features native-metadata --no-deps

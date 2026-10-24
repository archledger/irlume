#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Declared fixture relationships only; this cannot authorize loading.
set -euo pipefail
cd "$(dirname -- "$0")/.."
export RUSTDOCFLAGS='-D warnings'
graph_tests() {
  local min=18
  local extra=()
  if [[ ${1:-} == --evidence ]]; then
    shift
    min=20
    extra=(--require real_observer_buffers_feed_sparse_ids_with_explicit_path_remapping
      --require complete_observation_bijections_reject_repeated_indices_and_ids)
  fi
  scripts/run-tests-guarded.sh --min "$min" \
    --require generic_sparse_roots_resolve_real_parsed_transitive_cycles \
    --require repeated_needed_edges_keep_dynamic_order \
    --require input_ids_and_digests_are_exact_bijections \
    --require empty_duplicate_missing_roots_and_unreachable_members_refuse \
    --require aliases_and_sonames_have_one_explicit_library_owner \
    --require executable_interpreter_binding_is_explicit_distinct_and_exact \
    --require executable_without_interpreter_and_library_only_graphs_work \
    --require runpath_templates_are_fixture_only_and_duplicates_refuse \
    --require active_tag_and_flag_policy_ignores_ineffective_trailing_entries \
    --require roots_paths_aliases_and_needed_names_are_bounded \
    --require malformed_elf_is_rejected_after_its_exact_digest_matches \
    --require graph_is_borrowed_descriptive_and_does_not_replace_certification \
    --require graph_owned_reservations_fail_without_partial_success \
    --require content_and_path_budgets_use_checked_math_without_large_allocations \
    --require interpreter_and_repeated_needed_edges_share_one_budget \
    --require node_root_and_alias_count_ceilings_are_enforced \
    --require executable_bindings_reject_missing_nonroot_and_foreign_interpreters \
    --require active_string_table_duplicates_and_header_flags_refuse \
    "${extra[@]}" -- cargo test --locked -p irlume-vision "$@" --lib native_generation::
}
graph_tests --no-default-features --features native-metadata
cargo clippy --locked -p irlume-vision --no-default-features --features native-metadata --all-targets -- -D warnings
graph_tests --features npu,native-metadata
scripts/run-tests-guarded.sh --min 2 -- \
  cargo test --locked -p irlume-vision --no-default-features --features native-metadata --doc native_generation
cargo doc --locked -p irlume-vision --no-default-features --features native-metadata --no-deps
export RUSTFLAGS='--cfg irlume_hw_evidence'
export RUSTDOCFLAGS='--cfg irlume_hw_evidence -D warnings'
graph_tests --evidence --features npu,native-metadata
cargo clippy --locked -p irlume-vision --features npu,native-metadata --all-targets -- -D warnings
scripts/run-tests-guarded.sh --min 2 -- \
  cargo test --locked -p irlume-vision --features npu,native-metadata --doc native_generation
cargo doc --locked -p irlume-vision --features npu,native-metadata --no-deps

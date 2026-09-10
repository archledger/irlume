#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Prepare coverage on either rolling-Arch runner without changing its user tools.
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

# These runners use distro Rust, so rustup's llvm-tools component is not the
# source of the reporting tools. Refuse incompatible profile readers early.
rust_version=$(rustc -vV)
rust_llvm=$(sed -nE 's/^LLVM version: ([0-9]+)\..*/\1/p' <<<"$rust_version")
[[ "$rust_llvm" =~ ^[0-9]+$ ]] || { echo 'Cannot determine rustc LLVM version' >&2; exit 1; }
llvm_cov=$(command -v llvm-cov)
llvm_profdata=$(command -v llvm-profdata)
for tool in "$llvm_cov" "$llvm_profdata"; do
  version=$("$tool" --version)
  major=$(sed -nE 's/.*[Vv]ersion ([0-9]+)\..*/\1/p' <<<"$version")
  if [[ "$major" != "$rust_llvm" ]]; then
    echo "LLVM mismatch: $tool reports '$major', rustc uses '$rust_llvm'" >&2
    exit 1
  fi
done

# An existing cargo subcommand may be missing, stale or outside PATH. Always
# install the reviewed version into this job's temporary directory and invoke
# its absolute path; Cargo can also discover old tools in CARGO_HOME/bin.
tool_dir=$(mktemp -d "${RUNNER_TEMP%/}/irlume-coverage-tools.XXXXXX")
cargo install cargo-llvm-cov --version 0.9.1 --locked \
  --root "$tool_dir" --target-dir "$tool_dir/build"
coverage_bin="$tool_dir/bin/cargo-llvm-cov"
version=$("$coverage_bin" llvm-cov --version)
[[ "$version" == 'cargo-llvm-cov 0.9.1' ]] || { echo "Unexpected coverage tool: $version" >&2; exit 1; }
printf '%s\n' "$version" "LLVM major: $rust_llvm"
# Publish only after every prerequisite passed. RUNNER_TEMP is cleaned by the
# runner after the job; no sudo, persistent PATH or Cargo-home changes needed.
printf 'IRLUME_COVERAGE_BIN=%s\nLLVM_COV=%s\nLLVM_PROFDATA=%s\n' \
  "$coverage_bin" "$llvm_cov" "$llvm_profdata" >> "$GITHUB_ENV"

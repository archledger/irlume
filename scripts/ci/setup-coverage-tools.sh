#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
# Prepare coverage tools for a CI job without changing the runner's user tools.
#
# Usage: setup-coverage-tools.sh [system|rustup]
#
# system (default, the nightly hardware suite): the runner uses distro Rust,
# built against the system LLVM, so rustup's llvm-tools component is not the
# source of the reporting tools. The system llvm-cov/llvm-profdata are used
# and must match rustc's LLVM major.
#
# rustup (the hosted coverage lane, .github/workflows/coverage.yml): rustc
# comes from a rustup-managed toolchain that carries the llvm-tools-preview
# component, and no system llvm-cov is guaranteed to be paired with it. The
# readers come from the active toolchain's sysroot and are version-checked
# the same way, so a broken or mismatched component fails here, before any
# test capture.
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

mode="${1:-system}"
case "$mode" in
  system | rustup) ;;
  *)
    echo "usage: $0 [system|rustup]; unknown mode: $mode" >&2
    exit 2
    ;;
esac

rust_version=$(rustc -vV)
rust_llvm=$(sed -nE 's/^LLVM version: ([0-9]+)\..*/\1/p' <<<"$rust_version")
[[ "$rust_llvm" =~ ^[0-9]+$ ]] || { echo 'Cannot determine rustc LLVM version' >&2; exit 1; }

case "$mode" in
  system)
    llvm_cov=$(command -v llvm-cov)
    llvm_profdata=$(command -v llvm-profdata)
    ;;
  rustup)
    # The toolchain that builds the instrumented binaries must also supply
    # the readers: a distro llvm-cov of another LLVM major would be caught
    # by the check below, but only after picking up an unrelated binary. Go
    # to the sysroot directly.
    sysroot=$(rustc --print sysroot)
    host=$(sed -nE 's/^host: (.+)$/\1/p' <<<"$rust_version")
    [[ -n "$host" ]] || { echo 'Cannot determine rustc host triple' >&2; exit 1; }
    tool_bin="$sysroot/lib/rustlib/$host/bin"
    for tool in llvm-cov llvm-profdata; do
      if [ ! -x "$tool_bin/$tool" ]; then
        echo "rustup mode: $tool_bin/$tool is missing or not executable" >&2
        echo "The toolchain needs its llvm-tools-preview component; the" >&2
        echo "rust-toolchain step must name it in components:" >&2
        exit 1
      fi
    done
    llvm_cov="$tool_bin/llvm-cov"
    llvm_profdata="$tool_bin/llvm-profdata"
    ;;
esac

# Refuse incompatible profile readers early, in both modes: a reader that
# cannot parse this rustc's profiles turns the report into a hard error or,
# worse, a silent zero.
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
printf '%s\n' "mode: $mode" "$version" "LLVM major: $rust_llvm"
# Publish only after every prerequisite passed. RUNNER_TEMP is cleaned by the
# runner after the job; no sudo, persistent PATH or Cargo-home changes needed.
printf 'IRLUME_COVERAGE_BIN=%s\nLLVM_COV=%s\nLLVM_PROFDATA=%s\n' \
  "$coverage_bin" "$llvm_cov" "$llvm_profdata" >> "$GITHUB_ENV"

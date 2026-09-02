#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 EXPECTED_SHA OUTPUT_JSON" >&2
    exit 2
fi

expected_sha=$1
output_json=$2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
worktree=$(git -C "$script_dir" rev-parse --show-toplevel)
actual_sha=$(git -C "$worktree" rev-parse HEAD)
if [ "$actual_sha" != "$expected_sha" ]; then
    echo "openvino-hardware: exact-head mismatch: expected $expected_sha, got $actual_sha" >&2
    exit 1
fi
if [ -n "$(git -C "$worktree" status --porcelain --untracked-files=all)" ]; then
    echo "openvino-hardware: source tree is dirty" >&2
    exit 1
fi

runtime_root="/tmp/opencode/npu-spike"
matrix="$worktree/packaging/openvino/matrix.toml"
python3 "$worktree/scripts/check-openvino-matrix.py" --matrix "$matrix"

matrix_value() {
    python3 - "$matrix" "$1" <<'PY'
import pathlib
import sys
import tomllib

with pathlib.Path(sys.argv[1]).open("rb") as source:
    print(tomllib.load(source)[sys.argv[2]])
PY
}

expected_openvino=$(matrix_value openvino)
expected_level_zero_tag=$(matrix_value level_zero_tag)
expected_level_zero_commit=$(matrix_value level_zero_commit)
expected_npu_userspace=$(matrix_value npu_userspace)
npu_python="$runtime_root/venv/bin/python"
level_zero_source="$runtime_root/downloads/level-zero-$expected_level_zero_tag"
level_zero_libs="$runtime_root/runtime/level-zero/lib64"
npu_libs="$runtime_root/runtime/usr/lib/x86_64-linux-gnu"
openvino_libs=$(
    "$npu_python" -c 'import pathlib, openvino; print((pathlib.Path(openvino.__file__).resolve().parent / "libs").resolve())'
)
case "$openvino_libs" in
    "$runtime_root"/*) ;;
    *) echo "openvino-hardware: OpenVINO resolved outside the verified runtime root" >&2; exit 1 ;;
esac
actual_openvino=$("$npu_python" -c 'import openvino; print(openvino.__version__)')
if [ "$actual_openvino" != "$expected_openvino" ]; then
    echo "openvino-hardware: OpenVINO runtime differs from matrix" >&2
    exit 1
fi
if [ "$(git -C "$level_zero_source" rev-parse HEAD)" != "$expected_level_zero_commit" ]; then
    echo "openvino-hardware: Level Zero source differs from matrix" >&2
    exit 1
fi
level_zero_version=${expected_level_zero_tag#v}
npu_library_version=$(python3 - "$expected_npu_userspace" <<'PY'
import re
import sys

match = re.match(r"[0-9]+\.[0-9]+\.[0-9]+", sys.argv[1])
if match is None:
    raise SystemExit("invalid NPU userspace version")
print(match.group(0))
PY
)
ze_driver="$npu_libs/libze_intel_npu.so.$npu_library_version"
onnx_frontends=("$openvino_libs"/libopenvino_onnx_frontend.so.*)
c_apis=("$openvino_libs"/libopenvino_c.so.*)
if [ "${#onnx_frontends[@]}" -ne 1 ] || [ ! -f "${onnx_frontends[0]}" ]; then
    echo "openvino-hardware: expected one OpenVINO ONNX frontend" >&2
    exit 1
fi
if [ "${#c_apis[@]}" -ne 1 ] || [ ! -f "${c_apis[0]}" ]; then
    echo "openvino-hardware: expected one versioned OpenVINO C API library" >&2
    exit 1
fi
for required in \
    "$level_zero_libs/libze_loader.so.$level_zero_version" \
    "$ze_driver" \
    "$openvino_libs/libopenvino_intel_npu_plugin.so"; do
    if [ ! -f "$required" ]; then
        echo "openvino-hardware: verified runtime component is missing" >&2
        exit 1
    fi
done

output_parent=$(dirname -- "$output_json")
if [ -L "$output_json" ] || [ ! -d "$output_parent" ] \
    || [ "$(realpath "$output_parent")" != "$output_parent" ] \
    || [ "$(stat -c %u "$output_parent")" != "$(id -u)" ]; then
    echo "openvino-hardware: unsafe evidence output path" >&2
    exit 1
fi

umask 077
scratch=$(mktemp -d)
evidence_tmp=$(mktemp "$output_parent/.openvino-evidence.XXXXXX")
cleanup() {
    rm -rf -- "$scratch"
    rm -f -- "$evidence_tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export CARGO_TARGET_DIR="$scratch/cargo-target"
mkdir "$scratch/openvino-link"
ln -s -- "${c_apis[0]}" "$scratch/openvino-link/libopenvino_c.so"
runtime_path="$scratch/openvino-link:$openvino_libs:$level_zero_libs:$npu_libs"
runtime_env=(
    "LD_LIBRARY_PATH=$runtime_path"
    "ZE_ENABLE_ALT_DRIVERS=$ze_driver"
    "IRLUME_EXECUTION_DEVICE=npu"
)
cd "$worktree"

(
    cd "$worktree/models"
    sha256sum --check --strict SHA256SUMS
)
env "${runtime_env[@]}" "$worktree/scripts/run-tests-guarded.sh" \
    --require every_manifest_onnx_model_runs_deterministically_on_exact_npu -- \
    cargo test -p irlume-vision --locked --features experimental-openvino \
    every_manifest_onnx_model_runs_deterministically_on_exact_npu -- \
    --ignored --nocapture --test-threads=1
env "${runtime_env[@]}" cargo test -p irlume-vision --locked --features experimental-openvino \
    available_devices_are_sanitized_and_assignment_must_be_exact -- --test-threads=1
env "${runtime_env[@]}" cargo test -p irlume-vision --locked --features experimental-openvino \
    openvino_cache_is_versioned_and_distinguishes_clean_warm_and_changed_runtime -- --test-threads=1
env "${runtime_env[@]}" cargo test -p irlume-vision --locked --features experimental-openvino \
    openvino_cache_rebuild_is_bounded_to_one_clear -- --test-threads=1
env "${runtime_env[@]}" "$npu_python" "$worktree/benchmarks/bench_npu_models.py" \
    --models-dir "$worktree/models" --manifest "$worktree/models/SHA256SUMS" >"$scratch/models.json"
env "${runtime_env[@]}" "$npu_python" "$worktree/benchmarks/bench_npu_pipeline.py" \
    --models-dir "$worktree/models" --manifest "$worktree/models/SHA256SUMS" >"$scratch/pipeline.json"
python3 "$worktree/scripts/hardware/validate-openvino-hardware.py" \
    --models "$scratch/models.json" \
    --pipeline "$scratch/pipeline.json" \
    --matrix "$matrix" \
    --commit "$expected_sha" \
    --rust-adapter-passed \
    --assignment-negative-passed \
    --cache-contracts-passed >"$evidence_tmp"
if [ "$(stat -c %s "$evidence_tmp")" -gt 65536 ]; then
    echo "openvino-hardware: bounded evidence exceeds 64 KiB" >&2
    exit 1
fi
mv -- "$evidence_tmp" "$output_json"
evidence_tmp=""
echo "openvino-hardware: PASS evidence=$output_json"

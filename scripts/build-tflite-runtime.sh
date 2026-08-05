#!/bin/bash
# Build irlume's bundled TFLite C runtime (libtensorflowlite_c.so) from a
# pinned TensorFlow tag, for the #295 packaging lane.
#
# Google publishes no prebuilt Linux x86_64 C-API artifact with stable URLs
# (the Maven AAR and Python wheels are the wrong shape), so irlume builds
# this once per pin, publishes the tarball on its own GitHub release
# (tflite-runtime-<TF_TAG>), and every packaging lane consumes that artifact
# by sha256 exactly the way they consume the pinned onnxruntime tarball.
#
# The build itself is the documented CMake path (tensorflow/lite/c), XNNPACK
# on. Inputs are pinned by the TF_TAG git tag; the third-party dependencies
# are fetched by CMake at configure time from the commit pins recorded in
# tensorflow/lite/tools/cmake/modules/*.cmake, so the full input set is
# determined by the tag. The output is NOT claimed to be bit-reproducible;
# the recipe plus the published sha256 is the trust chain, same as any
# release asset here.
#
# Measured 2026-08-05 on a 2.2GHz-capped Zenbook: 210s at -j8, 8.2MB .so.
#
# Usage: scripts/build-tflite-runtime.sh [work_dir]
#   Produces work_dir/libtensorflowlite_c-<TF_TAG>-linux-x64.tar.gz and
#   prints its sha256. Needs: git, cmake >= 3.16, a C++17 toolchain, network
#   (for the TF clone and CMake's dependency fetches).
set -euo pipefail

# The TF tag every consumer of this artifact is pinned to. Bump deliberately:
# the runtime and the edgefirst-tflite binding version range move together
# (0.9.0 states TFLite 2.14+).
TF_TAG="v2.19.0"

WORK="${1:-$(pwd)/tflite-runtime-build}"
SRC="$WORK/tensorflow"
BUILD="$WORK/build"
OUT="$WORK/libtensorflowlite_c-${TF_TAG}-linux-x64"

mkdir -p "$WORK"
if [ ! -d "$SRC/.git" ]; then
    git clone --depth 1 --branch "$TF_TAG" https://github.com/tensorflow/tensorflow.git "$SRC"
fi
ACTUAL_TAG=$(git -C "$SRC" describe --tags)
if [ "$ACTUAL_TAG" != "$TF_TAG" ]; then
    echo "refusing: checkout is $ACTUAL_TAG, not $TF_TAG" >&2
    exit 1
fi

mkdir -p "$BUILD"
# CMAKE_POLICY_VERSION_MINIMUM: several of TF's vendored deps (neon2sse among
# them) declare pre-3.5 minimums that current CMake refuses outright.
cmake -S "$SRC/tensorflow/lite/c" -B "$BUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DTFLITE_ENABLE_XNNPACK=ON
cmake --build "$BUILD" -j "$(nproc)"

test -f "$BUILD/libtensorflowlite_c.so"
mkdir -p "$OUT/lib"
cp "$BUILD/libtensorflowlite_c.so" "$OUT/lib/"
# The licenses ride with the binary: the runtime is Apache-2.0 and the
# bundled artifact must say so on its own.
cp "$SRC/LICENSE" "$OUT/LICENSE.tensorflow"
{
    echo "libtensorflowlite_c.so built from tensorflow $TF_TAG"
    echo "recipe: scripts/build-tflite-runtime.sh (irlume repo)"
    echo "commit: $(git -C "$SRC" rev-parse HEAD)"
} > "$OUT/PROVENANCE"

TAR="$WORK/libtensorflowlite_c-${TF_TAG}-linux-x64.tar.gz"
tar -C "$WORK" -czf "$TAR" "$(basename "$OUT")"
sha256sum "$TAR"

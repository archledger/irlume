#!/usr/bin/env bash
# Fetch irlume's ONNX model weights from the `models-v1` GitHub release and
# verify them by sha256. This replaces `git lfs pull`: the weights are static
# (they do not change between releases) and are hosted as release assets, which
# are NOT counted against the account's Git LFS bandwidth quota. So CI, the AUR
# PKGBUILD, and the .deb/PPA builds get the models without draining the 10 GB/mo
# LFS bandwidth (a full pull is ~266 MB, so a few dozen builds exhausted it).
#
# Idempotent: a model already present with the right hash is left untouched, so
# a local dev tree that already has the weights does no network at all.
#
# Usage: bash scripts/fetch-models.sh [DEST_DIR]   (DEST_DIR defaults to ./models)
# Override the source with IRLUME_MODELS_REPO / IRLUME_MODELS_TAG.
set -euo pipefail

REPO="${IRLUME_MODELS_REPO:-archledger/irlume}"
TAG="${IRLUME_MODELS_TAG:-models-v1}"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
DEST="${1:-$(cd "$(dirname "$0")/.." && pwd)/models}"

command -v curl >/dev/null || { echo "fetch-models: need curl" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "fetch-models: need sha256sum" >&2; exit 1; }

# name  sha256 (must match the assets on the models-v1 release; bump the tag to
# models-v2 and update these if a weight ever changes).
verify_or_fetch() {
    local name="$1" sha="$2" out="$DEST/$1"
    if [ -f "$out" ] && [ "$(sha256sum "$out" | cut -d' ' -f1)" = "$sha" ]; then
        echo "fetch-models: $name present and verified"
        return 0
    fi
    echo "fetch-models: downloading $name"
    curl -fSL --retry 3 --retry-delay 2 -o "$out.tmp" "$BASE/$name"
    local got
    got=$(sha256sum "$out.tmp" | cut -d' ' -f1)
    if [ "$got" != "$sha" ]; then
        echo "fetch-models: CHECKSUM MISMATCH for $name (want $sha, got $got)" >&2
        rm -f "$out.tmp"
        return 1
    fi
    mv -f "$out.tmp" "$out"
    echo "fetch-models: $name OK"
}

mkdir -p "$DEST"
verify_or_fetch glintr100.onnx                   a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60
verify_or_fetch face_detection_yunet_2023mar.onnx 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4
verify_or_fetch face_landmark.onnx               821683be088447839638f79d64268bd501bdb72e5d9e262ec981c7e252956caf
verify_or_fetch blaze_face_short_range.onnx      c5453678015f6289c1d77bda88a8ba9c87574f01de1a05ba1909b9a7e08b237b
verify_or_fetch face_landmarks_detector.tflite    c7d54204ce0448474c7f3fa9af494787c0965cbdd6f20fc72867e43046bd43d5
verify_or_fetch liveness_vit.onnx                 c7f8a6f3054b11f9719f5e24d37ec227721608fff8b90373c6c3e7659864161c
verify_or_fetch flir.onnx                         df80cea7228b92562692e56aac965d35766c77399159798c552fb3c77b410c72
echo "fetch-models: all model weights present in $DEST"

#!/bin/bash
# Run scripts/build-tflite-runtime.sh inside ubuntu:22.04, the oldest system
# the universal .deb advertises (glibc 2.35, GCC-12-era libstdc++). The
# artifact's symbol-version floor is set by the BUILD environment, and the
# first published build (made on Fedora 44) demanded GLIBC_2.43 and
# GLIBCXX_3.4.32, which cannot load on the very systems the package
# declares support for (#297 review). The script's own floor guards then
# refuse any future artifact that regresses.
#
# Usage: scripts/build-tflite-runtime-container.sh [work_dir]
set -euo pipefail
WORK="${1:-$(pwd)/tflite-runtime-build}"
mkdir -p "$WORK"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
podman run --rm \
    -v "$REPO/scripts/build-tflite-runtime.sh:/build.sh:ro,Z" \
    -v "$WORK:/work:Z" \
    docker.io/library/ubuntu:22.04 \
    bash -ec 'apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -qy --no-install-recommends git cmake make g++ python3 ca-certificates binutils >/dev/null && bash /build.sh /work'

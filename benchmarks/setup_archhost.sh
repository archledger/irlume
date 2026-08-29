#!/usr/bin/env bash
# Idempotent archhost bootstrap for the irlume calibration campaign.
# Creates the pinned Python 3.12 venv and installs requirements-bench.txt.
set -euo pipefail

VENV="${VENV:-$HOME/venvs/bench}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! command -v uv >/dev/null 2>&1; then
    echo "uv not found. Install it first: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
    uv venv "$VENV" --python 3.12
fi

uv pip install --python "$VENV/bin/python" -r "$HERE/requirements-bench.txt"

"$VENV/bin/python" - <<'EOF'
import cv2, numpy, requests, pytest  # noqa: F401
import onnxruntime as ort
print("cv2", cv2.__version__)
print("numpy", numpy.__version__)
print("ort", ort.__version__, ort.get_available_providers())
EOF
echo "OK: $VENV ready"

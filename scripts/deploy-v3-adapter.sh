#!/usr/bin/env bash
# Deploy the v3 (residZero) IR adapter build. Run with sudo.
#   sudo bash scripts/deploy-v3-adapter.sh   (from the repo root)
# Revert:  sudo bash scripts/deploy-v3-adapter.sh --revert
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN=/usr/local/bin
SRC="$REPO/target/release"

if [[ "${1:-}" == "--revert" ]]; then
  echo "[revert] restoring pre-v3 binaries + v1 adapter"
  cp -a "$BIN/irlumed.pre-v3" "$BIN/irlumed"
  cp -a "$BIN/irlume.pre-v3"  "$BIN/irlume"
  cp -a "$REPO"/models/ir_adapter.onnx.v1-256 "$REPO"/models/ir_adapter.onnx
  systemctl restart irlumed
  echo "[revert] done — restart the daemon, then RE-ENROLL again (v1 256-D space)."
  echo "         (or restore enrollment: cp ~/.local/share/irlume/\$USER.json.pre-v3adapter ~/.local/share/irlume/\$USER.json)"
  exit 0
fi

echo "[deploy] backing up current binaries -> .pre-v3"
cp -a "$BIN/irlumed" "$BIN/irlumed.pre-v3"
cp -a "$BIN/irlume"  "$BIN/irlume.pre-v3"
echo "[deploy] installing v3 build"
install -m0755 "$SRC/irlumed" "$BIN/irlumed"
install -m0755 "$SRC/irlume"  "$BIN/irlume"
echo "[deploy] restarting daemon"
systemctl restart irlumed
sleep 1
systemctl is-active irlumed
echo "[deploy] done. Verify adapter with:"
echo "  journalctl -u irlumed -b --no-pager | grep -i 'IR adapter' | tail -1"

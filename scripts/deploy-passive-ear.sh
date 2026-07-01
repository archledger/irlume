#!/usr/bin/env bash
# Deploy the passive-EAR liveness build (HEAD >= a8d839d) and wire the
# FaceMesh model into the daemon unit. Run as root from the repo root.
#   sudo bash scripts/deploy-passive-ear.sh          # deploy
#   sudo bash scripts/deploy-passive-ear.sh --revert # restore pre-deploy state
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN=/usr/local/bin
DROPIN_DIR=/etc/systemd/system/irlumed.service.d
DROPIN="$DROPIN_DIR/10-mesh.conf"
MESH="$REPO/models/face_landmark.onnx"

if [[ "${1:-}" == "--revert" ]]; then
    for b in irlumed irlume; do
        [[ -f "$BIN/$b.pre-passive-ear" ]] && cp -p "$BIN/$b.pre-passive-ear" "$BIN/$b"
    done
    rm -f "$DROPIN"
    systemctl daemon-reload
    systemctl restart irlumed
    echo "reverted: pre-passive-ear binaries restored, mesh drop-in removed"
    exit 0
fi

[[ -f "$MESH" ]] || { echo "missing $MESH" >&2; exit 1; }

for b in irlumed irlume; do
    [[ -f "$BIN/$b.pre-passive-ear" ]] || cp -p "$BIN/$b" "$BIN/$b.pre-passive-ear"
    install -m 0755 "$REPO/target/release/$b" "$BIN/$b"
done

mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<EOF
[Service]
Environment="IRLUME_MESH_MODEL=$MESH"
EOF

systemctl daemon-reload
systemctl restart irlumed
sleep 1
systemctl is-active irlumed
journalctl -u irlumed -n 5 --no-pager
echo "deployed: $(md5sum "$BIN/irlumed" "$BIN/irlume")"

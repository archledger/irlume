#!/usr/bin/env bash
# Install the irlume daemon + CLI on this host from a built repo checkout.
# Cross-distro (Fedora/Arch/Debian-family): binaries + systemd unit only; PAM
# wiring is a separate, distro-specific step. Run as root from the repo root:
#   sudo bash scripts/install-host.sh --ort /path/to/libonnxruntime.so
set -euo pipefail

ORT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ort) ORT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
[[ -n "$ORT" && -f "$ORT" ]] || { echo "need --ort <libonnxruntime.so> (found: '$ORT')" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
for b in irlumed irlume; do
    [[ -f "$REPO/target/release/$b" ]] || { echo "missing $REPO/target/release/$b; build first" >&2; exit 1; }
done
for m in face_detection_yunet_2023mar.onnx glintr100.onnx face_landmark.onnx blaze_face_short_range.onnx; do
    [[ -f "$REPO/models/$m" ]] || { echo "missing $REPO/models/$m" >&2; exit 1; }
done

# State lives under the invoking user's home (single-admin install for now).
STATE_HOME="$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)"

install -m 0755 "$REPO/target/release/irlumed" "$REPO/target/release/irlume" /usr/local/bin/

cat > /etc/systemd/system/irlumed.service <<EOF
[Unit]
Description=irlume face authentication daemon
After=multi-user.target

[Service]
Type=simple
ExecStart=/usr/local/bin/irlumed
Environment="ORT_DYLIB_PATH=$ORT"
Environment="IRLUME_DET_MODEL=$REPO/models/face_detection_yunet_2023mar.onnx"
Environment="IRLUME_MODEL=$REPO/models/glintr100.onnx"
Environment="IRLUME_MESH_MODEL=$REPO/models/face_landmark.onnx"
Environment="IRLUME_BLAZE_MODEL=$REPO/models/blaze_face_short_range.onnx"
Environment="IRLUME_SOCKET=/run/irlume.sock"
Environment="IRLUME_STATE_DIR=$STATE_HOME/.local/share/irlume"
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now irlumed
sleep 1
systemctl is-active irlumed
journalctl -u irlumed -n 6 --no-pager

#!/bin/sh
set -e
# Load the AppArmor profile FIRST so the daemon is confined at start (AppArmor
# binds confinement at exec time; the profile enforces, soak-validated). Then
# try-restart picks up confinement on an upgrade where the daemon is already
# running (enable --now is a no-op for a running unit).
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r /etc/apparmor.d/usr.bin.irlumed 2>/dev/null || true
fi
systemctl daemon-reload 2>/dev/null || true
systemctl enable --now irlumed.service 2>/dev/null || true
systemctl try-restart irlumed.service 2>/dev/null || true
cat <<'EOF'
irlume installed. Next steps:
  irlume tui                         # enroll your face + configure
  sudo irlume login enable --apply   # opt-in: wire greeter/lock screen
(enrollment auto-enables the 850nm IR emitter when IR frames are black;
 manual fallback for IR cameras: sudo irlume ir-setup)
Password is always the fallback; no lockout.
EOF

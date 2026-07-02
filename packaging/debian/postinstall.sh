#!/bin/sh
set -e
systemctl daemon-reload 2>/dev/null || true
systemctl enable --now irlumed.service 2>/dev/null || true
# Load the AppArmor profile (ships in complain mode; flip to enforce after a
# full enroll/verify/lock-screen exercise — see the profile header).
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r -W /etc/apparmor.d/usr.bin.irlumed 2>/dev/null || true
fi
cat <<'EOF'
irlume installed. Next steps:
  irlume ir-setup                    # enable the 850nm IR emitter (once)
  irlume tui                         # enroll your face + configure
  sudo irlume login enable --apply   # opt-in: wire greeter/lock screen
Password is always the fallback — no lockout.
EOF

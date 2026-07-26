#!/bin/sh
set -e
# Load the AppArmor profile FIRST so the daemon is confined at start (AppArmor
# binds confinement at exec time; the profile enforces, soak-validated). Then
# try-restart picks up confinement on an upgrade where the daemon is already
# running (enable --now is a no-op for a running unit).
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r /etc/apparmor.d/usr.bin.irlumed 2>/dev/null || true
fi
# Create the `irlume` system group so the daemon can restrict its socket to
# 0660 root:irlume (Debian/Ubuntu do not run sysusers.d automatically).
systemd-sysusers /usr/lib/sysusers.d/irlume.conf 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
# Enable + start ONLY on first install ($2 empty). On an upgrade, re-enabling
# would override a unit the user deliberately disabled; try-restart below picks
# up the new binary/unit for a running daemon and is a no-op for a stopped one.
if [ -z "${2:-}" ]; then
    systemctl enable --now irlumed.service 2>/dev/null || true
    # Watches greeter PAM files and re-applies irlume wiring after a distro
    # update strips it. Self-gates on the login.wired marker, so it stays idle
    # until `irlume login enable` runs.
    systemctl enable --now irlume-reconcile.path 2>/dev/null || true
    # Backstop: the path unit does not see a file replaced by rename.
    systemctl enable --now irlume-reconcile.timer 2>/dev/null || true
    # The .service runs at boot + on PAM change; --now runs one reconcile so an
    # upgrade adopts an already-wired install into the self-heal marker and a
    # same-transaction strip is re-applied. Self-gates; no-op on a fresh box.
    systemctl enable --now irlume-reconcile.service 2>/dev/null || true
fi
# The timer is NEW in 0.7.0, and the block above only enables units on FIRST
# install so an upgrade cannot re-enable something the admin turned off. That
# would leave every upgrader without the backstop, which is exactly the
# population the self-heal exists for (issue #93). Arm it ONCE, recorded by a
# marker, so a later deliberate `systemctl disable` is still respected.
if [ ! -e /var/lib/irlume/.reconcile-timer-armed ]; then
    mkdir -p /var/lib/irlume
    systemctl enable --now irlume-reconcile.timer 2>/dev/null || true
    : > /var/lib/irlume/.reconcile-timer-armed
fi
systemctl try-restart irlumed.service 2>/dev/null || true
cat <<'EOF'
irlume installed. Next steps:
  irlume tui                         # enroll your face + configure
  sudo irlume login enable --apply   # opt-in: wire greeter/lock screen
(enrollment auto-enables the 850nm IR emitter when IR frames are black;
 manual fallback for IR cameras: sudo irlume ir-setup)
Password is always the fallback; no lockout.
EOF

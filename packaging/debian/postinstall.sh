#!/bin/sh
set -e
# Load the AppArmor profile FIRST so the daemon is confined at start (AppArmor
# binds confinement at exec time; the profile enforces, soak-validated). Then
# try-restart picks up confinement on an upgrade where the daemon is already
# running (enable --now is a no-op for a running unit).
if command -v apparmor_parser >/dev/null 2>&1; then
    # SAY SO on failure. This used to discard both the output and the status, so
    # when the profile declared an ABI the installed parser did not have, every
    # Debian 12 and Ubuntu 22.04 install came up UNCONFINED and the package still
    # exited 0. The load is still not fatal (a machine with AppArmor disabled in
    # the kernel is a normal configuration, and refusing to install there would be
    # worse), but a confinement that did not take is not something to hide.
    if ! apparmor_parser -r /etc/apparmor.d/usr.bin.irlumed 2>&1; then
        echo "irlume: WARNING: the AppArmor profile did not load; irlumed will" >&2
        echo "irlume: run unconfined. Report the parser error above." >&2
    fi
fi
systemctl daemon-reload 2>/dev/null || true
# Enable + start ONLY on first install ($2 empty). On an upgrade, re-enabling
# would override a unit the user deliberately disabled; try-restart below picks
# up the new binary/unit for a running daemon and is a no-op for a stopped one.
if [ -z "${2:-}" ]; then
    # The socket first: see packaging/systemd/irlumed.socket (#244).
    systemctl enable --now irlumed.socket irlumed.service 2>/dev/null || true
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
# Run one reconcile on UPGRADE too. The block above is fresh-install only, and
# its comment claimed the run made "an upgrade adopt an already-wired install"
# while sitting inside the branch an upgrade never takes: traced against the
# built package, `configure 0.8.1` called daemon-reload, is-enabled,
# enable-socket and try-restart, and no reconcile. Fedora's %post and Arch's
# post_upgrade both run it. It self-gates on the login.wired marker, so it is a
# no-op on a box that never wired login.
if [ -n "${2:-}" ]; then
    systemctl start irlume-reconcile.service 2>/dev/null || true
fi
# Upgrading from a version without the socket unit.
if systemctl is-enabled --quiet irlumed.service 2>/dev/null; then
    systemctl enable --now irlumed.socket 2>/dev/null || true
fi
systemctl try-restart irlumed.service 2>/dev/null || true
cat <<'EOF'
irlume installed. Next steps:
  irlume tui                         # enroll your face + configure
  sudo irlume login enable --apply   # opt-in: wire greeter/lock screen
(most Hello cameras need no emitter step; if IR frames stay dark,
 sudo irlume ir-setup writes to the camera and tells you so first)
Password is always the fallback; no lockout.
EOF

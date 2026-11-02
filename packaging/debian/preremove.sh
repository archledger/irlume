#!/bin/sh
set -e
# Only disable/stop on an actual removal, not on an upgrade (dpkg runs prerm
# with "upgrade" too): tearing the daemon down mid-upgrade, then having
# postinst re-enable it, churns state and would re-enable a unit the user
# deliberately disabled. On upgrade, postinst's try-restart handles the swap.
if [ "${1:-}" = remove ] && [ -z "${DPKG_ROOT:-}" ] && [ -d /run/systemd/system ]; then
    # These are pulled in by LightDM, not enabled independently. Stop the
    # triggers before their worker, but never stop the preparation unit:
    # LightDM Requires it, so stopping it would take the greeter down too.
    systemctl stop irlume-lightdm-refresh.path irlume-lightdm-refresh.timer 2>/dev/null || true
    systemctl stop irlume-lightdm-refresh.service 2>/dev/null || true
    systemctl disable --now irlumed.socket irlumed.service 2>/dev/null || true
    systemctl disable --now irlume-reconcile.path 2>/dev/null || true
    systemctl disable --now irlume-reconcile.timer 2>/dev/null || true
    systemctl disable --now irlume-reconcile.service 2>/dev/null || true
fi

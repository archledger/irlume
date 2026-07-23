#!/bin/sh
set -e
# Only disable/stop on an actual removal, not on an upgrade (dpkg runs prerm
# with "upgrade" too): tearing the daemon down mid-upgrade, then having
# postinst re-enable it, churns state and would re-enable a unit the user
# deliberately disabled. On upgrade, postinst's try-restart handles the swap.
if [ "$1" = remove ]; then
    systemctl disable --now irlumed.service 2>/dev/null || true
    systemctl disable --now irlume-reconcile.path 2>/dev/null || true
fi

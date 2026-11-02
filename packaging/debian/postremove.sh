#!/bin/sh
set -e
# The removed LightDM drop-in must leave the manager's dependency graph too.
# Reload only after removal, when the unit files and executable are gone;
# an upgrade still needs the old graph until postinstall loads its replacement.
case "${1:-}" in
    remove|purge)
        if [ -z "${DPKG_ROOT:-}" ] && [ -d /run/systemd/system ]; then
            systemctl daemon-reload 2>/dev/null || true
        fi
        ;;
esac

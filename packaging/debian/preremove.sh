#!/bin/sh
set -e
systemctl disable --now irlumed.service 2>/dev/null || true

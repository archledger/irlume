#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Read `irlume doctor` output and name the IR capture node, so the nightly
# hardware suite can point burst_dump at it.
#
# This exists as a file rather than an inline `awk` in hardware-suite.yml
# because the inline version silently disabled the camera stage for eight
# consecutive nights. `42c03c6` (2026-07-31, #195) appended the backend to
# every node line, turning
#
#     /dev/video2: Ir
# into
#     /dev/video2: Ir (uvcvideo, USB)
#
# and the workflow matched `/: Ir$/`, which anchors at end of line. From
# 2026-08-01 every scheduled run reported "classified 5 camera node(s) but
# none as Ir" on a runner whose own doctor output, printed directly beneath
# that error, said `/dev/video2: Ir (uvcvideo, USB)`. The strobe-burst
# capture is the only check in the whole repo that drives the real IR
# emitter, and none of those nights ran it.
#
# Two things follow, and both are load-bearing here:
#   1. The parse must tolerate anything doctor appends after the role token.
#   2. "I could not parse this" must be its own outcome. The old code had no
#      way to say it, so a format change arrived as "no IR node", which reads
#      as a hardware fact rather than as a broken parser.
#
# Usage:  ir-node-from-doctor.sh <file>   # file holds `irlume doctor` output
#         ir-node-from-doctor.sh --self-test
#
# Exit codes, which the caller is expected to branch on:
#   0   an IR node was found; its path is on stdout
#   10  doctor positively reported no camera nodes (a genuine absent-camera skip)
#   11  doctor listed nodes but classified none of them Ir (a regression)
#   12  the output did not parse (doctor's format changed; fix this script)
#   13  doctor could not establish what cameras exist (unreadable or unlistable)
#    2  usage error
set -euo pipefail

readonly EXIT_NO_NODES=10
readonly EXIT_NO_IR=11
readonly EXIT_UNPARSEABLE=12
readonly EXIT_CAMERA_UNKNOWN=13

readonly SECTION='[doctor] camera nodes (classified by pixel format):'

# The only line that asserts absence. doctor prints it under exactly one
# condition: no listing error, no classified nodes, AND no unreadable nodes
# (irlume-cli/src/main.rs, the `else if` beside the comment "Could not look is
# not nothing there").
#
# Requiring this marker, rather than inferring absence from a node count of
# zero, is what keeps a camera that is present but unreadable out of the skip
# path. A node denied by EACCES, held by another process, or lost to a failed
# /dev walk produces a section with no node lines and no absence marker, and
# counting those as "no camera" would let a permissions or contention
# regression retire the only test that drives the real emitter, green.
#
# The codebase already paid for this once at the layer below: #227 is the same
# defect, where dropping unreadable nodes from the report made a permission
# problem read as absent hardware. Inferring absence here would have reproduced
# it one level up (#383 review).
readonly ABSENCE_MARKER='(no /dev/video* nodes on this machine)'

# The node lines doctor writes are `  {path}: {role:?}{backend}{privacy}`
# (irlume-cli/src/main.rs, `dout!(report, "  {path}: {role:?}{backend}{priv_on}")`).
# `backend` and `privacy` are both empty or both start with a space, so the
# role token always ends at whitespace or end of line. Deeper-indented
# continuation lines (the MJPEG-only warning, the IPU note) are not node
# lines and must not be counted as one.
#
# Roles come from `irlume_camera::Role`; `Other` is a node correctly ignored
# (a UVC metadata node), so it counts as a listed node but never as IR. A
# role token outside this set means the enum grew and this script has not
# been taught about it, which is exit 12 and not a silent miss.
readonly KNOWN_ROLES='Rgb|Ir|Other'

parse() {
  local doc="$1"
  awk -v section="$SECTION" -v roles="$KNOWN_ROLES" -v absent="$ABSENCE_MARKER" '
    index($0, section) { in_section = 1; seen_section = 1; next }
    !in_section { next }
    # The section ends at the first line that is not indented under it.
    !/^[[:space:]]/ { in_section = 0; next }
    # doctor saying, positively, that this machine has no camera nodes.
    index($0, absent) { absence_stated = 1; next }
    # A node line, whatever doctor appends after the role.
    /^[[:space:]]+\/dev\/[^:]+:[[:space:]]/ {
      nodes++
      path = $0
      sub(/^[[:space:]]+/, "", path)
      sub(/:.*$/, "", path)
      role = $0
      sub(/^[[:space:]]+\/dev\/[^:]+:[[:space:]]+/, "", role)
      sub(/[[:space:]].*$/, "", role)
      if (role !~ ("^(" roles ")$")) { unknown_role = role; next }
      parsed++
      if (role == "Ir" && ir == "") ir = path
    }
    END {
      printf "%s|%d|%d|%s|%d|%d\n", ir, nodes + 0, parsed + 0, unknown_role, \
        seen_section + 0, absence_stated + 0
    }
  ' "$doc"
}

resolve() {
  local doc="$1" ir nodes parsed unknown seen absent
  # `|`, not a tab: tab is an IFS whitespace character, so `read` would strip
  # the leading empty field and shift every value one position left whenever
  # no IR node was found. That silently turned "no IR node" into "the IR node
  # is 2", which is the same class of defect this whole script exists for.
  IFS='|' read -r ir nodes parsed unknown seen absent < <(parse "$doc")

  # The section header itself is a format claim. Losing it means the parse
  # never even started, so nothing below it can be trusted.
  if [ "$seen" -eq 0 ]; then
    echo "doctor printed no '${SECTION}' section; its output format changed" >&2
    return "$EXIT_UNPARSEABLE"
  fi
  # Lines that look like nodes but carry a role this script does not know.
  if [ -n "$unknown" ]; then
    echo "doctor classified a node as '${unknown}', which is not one of ${KNOWN_ROLES}" >&2
    return "$EXIT_UNPARSEABLE"
  fi
  # Node lines present, none of which yielded a role: the line shape moved.
  # This is the case the old inline parser could not express, and it is the
  # one that actually happened.
  if [ "$nodes" -gt 0 ] && [ "$parsed" -eq 0 ]; then
    echo "doctor listed ${nodes} node line(s) and none parsed; its line format changed" >&2
    return "$EXIT_UNPARSEABLE"
  fi
  # Absence is only ever taken from doctor's own marker. A section with no node
  # lines and no marker means doctor could see nodes it could not read, or could
  # not walk /dev at all; either way what cameras exist is unknown, and unknown
  # must not license the skip that retires the emitter test.
  if [ "$nodes" -eq 0 ]; then
    if [ "$absent" -eq 1 ]; then
      echo "doctor reported no camera nodes on this machine" >&2
      return "$EXIT_NO_NODES"
    fi
    echo "doctor's camera section held neither a node nor the absence marker: \
nodes are present but unreadable (permissions, contention, driver), or /dev \
could not be walked. This is NOT an absent camera" >&2
    return "$EXIT_CAMERA_UNKNOWN"
  fi
  if [ -z "$ir" ]; then
    echo "doctor classified ${nodes} camera node(s), none of them Ir" >&2
    return "$EXIT_NO_IR"
  fi
  printf '%s\n' "$ir"
}

# --- self-test ---------------------------------------------------------------
# Runs in hosted CI on every PR. The point is that a doctor format change
# fails a job that takes seconds, instead of quietly parking the nightly
# camera stage until somebody reads a log.

self_test() {
  local tmp pass=0 fail=0
  tmp="$(mktemp -d)"
  # Removed explicitly at the end rather than from a trap: a RETURN or EXIT
  # trap set inside a function runs after that function has returned, so it
  # dereferences a `local` that is already out of scope and dies under
  # `set -u`. Nothing below exits early, so the explicit removal always runs.

  check() { # check <name> <expected-exit> <expected-stdout> <fixture-text>
    local name="$1" want_code="$2" want_out="$3" text="$4"
    local f="$tmp/fixture" got_out got_code=0
    printf '%s' "$text" >"$f"
    got_out="$(resolve "$f" 2>/dev/null)" || got_code=$?
    if [ "$got_code" -eq "$want_code" ] && [ "$got_out" = "$want_out" ]; then
      pass=$((pass + 1))
      printf '  ok   %s\n' "$name"
    else
      fail=$((fail + 1))
      printf '  FAIL %s: got exit %s out %-14s want exit %s out %s\n' \
        "$name" "$got_code" "'$got_out'" "$want_code" "'$want_out'"
    fi
  }

  # Verbatim from the 2026-08-08 nightly run (31281803049), the shape that
  # broke. The loopback nodes are the CI virtual-camera lane's, and they are
  # here on purpose: the IR node is not first in the list.
  check "current format, IR present" 0 "/dev/video2" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video0: Rgb (uvcvideo, USB)
  /dev/video2: Ir (uvcvideo, USB)
  /dev/video8: Rgb (v4l2 loopback, not USB)  ⚠ not the uvcvideo-on-USB case irlume is built for
[doctor] IR stream: 340x340@30.00fps GREY ✓
'
  # The pre-#195 bare line. Kept so the parse stays a superset rather than
  # trading one exact format for another.
  check "pre-#195 bare format" 0 "/dev/video2" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video0: Rgb
  /dev/video2: Ir
'
  check "privacy switch annotation" 0 "/dev/video2" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video2: Ir (uvcvideo, USB)  ⚠ PRIVACY SWITCH ON
'
  check "backend unreadable annotation" 0 "/dev/video2" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video2: Ir (backend unknown: no such file)  ⚠ could not identify camera backend
'
  # A deeper-indented continuation line must not be read as a node.
  check "continuation line is not a node" 0 "/dev/video2" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video0: Rgb (uvcvideo, USB)
     ⚠ offers only [MJPG]; irlume needs an uncompressed format
  /dev/video2: Ir (uvcvideo, USB)
'
  check "no nodes at all is a skip" "$EXIT_NO_NODES" "" \
'[doctor] camera nodes (classified by pixel format):
  (no /dev/video* nodes on this machine)
[doctor] TPM 2.0: /dev/tpmrm0 ✓
'
  # The three shapes that must NEVER reach the skip. Each one is a camera whose
  # state doctor could not establish, and the first version of this script
  # returned the absent-camera skip for all three, which would have let a
  # permissions or contention regression retire the emitter test green
  # (#383 review). Same defect as #227, one layer up.
  check "unreadable nodes are not absence" "$EXIT_CAMERA_UNKNOWN" "" \
'[doctor] camera nodes (classified by pixel format):
  ⚠ /dev/video0, /dev/video2: could not be opened: permission denied
[doctor] TPM 2.0: /dev/tpmrm0 ✓
'
  check "an unwalkable /dev is not absence" "$EXIT_CAMERA_UNKNOWN" "" \
'[doctor] camera nodes (classified by pixel format):
  ⚠ 2 entries in /dev could not be read; whether this machine has camera nodes is unknown
[doctor] TPM 2.0: /dev/tpmrm0 ✓
'
  check "an empty section is not absence" "$EXIT_CAMERA_UNKNOWN" "" \
'[doctor] camera nodes (classified by pixel format):
[doctor] TPM 2.0: /dev/tpmrm0 ✓
'
  check "nodes but none IR is a regression" "$EXIT_NO_IR" "" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video0: Rgb (uvcvideo, USB)
  /dev/video1: Other (uvcvideo, USB)
'
  check "missing section is unparseable" "$EXIT_UNPARSEABLE" "" \
'[doctor] TPM 2.0: /dev/tpmrm0 ✓
  /dev/video2: Ir (uvcvideo, USB)
'
  # The regression this script exists to catch: the role token moves and
  # every node line stops parsing. Must be exit 12, never exit 11.
  check "role token moved is unparseable" "$EXIT_UNPARSEABLE" "" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video0: [Rgb] (uvcvideo, USB)
  /dev/video2: [Ir] (uvcvideo, USB)
'
  check "unknown role is unparseable" "$EXIT_UNPARSEABLE" "" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video2: Thermal (uvcvideo, USB)
'
  # An IR node listed after the section closed belongs to some other report
  # and must not be picked up.
  check "match only inside the section" "$EXIT_NO_IR" "" \
'[doctor] camera nodes (classified by pixel format):
  /dev/video0: Rgb (uvcvideo, USB)
[doctor] some later section:
  /dev/video9: Ir (uvcvideo, USB)
'

  rm -rf "$tmp"
  printf '%d passed, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

main() {
  case "${1:-}" in
    --self-test) self_test ;;
    "" | -h | --help)
      echo "usage: $0 <doctor-output-file> | --self-test" >&2
      exit 2
      ;;
    *)
      [ -r "$1" ] || { echo "cannot read $1" >&2; exit 2; }
      resolve "$1"
      ;;
  esac
}

main "$@"

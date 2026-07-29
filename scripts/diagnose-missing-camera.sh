#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Read-only diagnosis for a camera that stopped appearing after irlume wrote to
# its UVC extension units (issue #159). Collects evidence and changes nothing.
#
# It sends the camera no USB requests of its own. Writing to a camera in this
# state is what caused the problem. No ordinary repair path is available either:
# UVC control and the usual firmware-update routes all run over USB control
# transfers, which require a device that still enumerates.
#
#   bash scripts/diagnose-missing-camera.sh > camera-report.txt 2>&1
#
# Run it right after a cold boot and attach the output to the issue.
set -uo pipefail

say() { printf '\n=== %s ===\n' "$1"; }

echo "irlume camera diagnosis, $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "This script only reads. It sends the camera nothing."

say "System"
uname -a
[ -r /sys/class/dmi/id/product_name ] && cat /sys/class/dmi/id/product_name
[ -r /sys/class/dmi/id/product_version ] && cat /sys/class/dmi/id/product_version
[ -r /sys/class/dmi/id/bios_version ] && cat /sys/class/dmi/id/bios_version

say "USB devices"
lsusb 2>&1 || echo "lsusb unavailable (install usbutils)"

say "USB topology"
lsusb -t 2>&1 || true

# 174f:11b4 is the camera as it normally appears. USB vendor 174f is registered
# to Syntek in the public usb.ids database, even though the device's own strings
# and the Windows driver say SunplusIT; the silicon vendor is not established.
# Any unfamiliar device appearing on the bus is worth reporting rather than
# writing to, since some camera controllers enumerate under a different ID when
# they are not running normal firmware.
say "Camera identity"
if lsusb 2>/dev/null | grep -qiE '174f:'; then
  lsusb | grep -iE '174f:'
else
  echo "The camera (174f:*) is not on the bus."
  echo "Full device list is above; report anything unfamiliar rather than writing to it."
fi

say "Video nodes"
find /dev -maxdepth 1 -type c \( -name 'video*' -o -name 'media*' \) -ls 2>/dev/null || true
find /sys/class/video4linux -maxdepth 2 -type l -print 2>/dev/null || echo "(none)"

# The distinction that matters most. A descriptor-read timeout means the port
# sees something electrically but the device will not answer control transfers.
# No event at all points at power, cable, or a disabled port instead.
say "Kernel USB events this boot"
if command -v journalctl >/dev/null 2>&1; then
  journalctl -k -b --no-pager 2>/dev/null \
    | grep -EiC1 'usb .*(error|descriptor|enumerate)|uvcvideo|over.?current|attempt power cycle' \
    | tail -60 || echo "(nothing matched)"
else
  dmesg 2>/dev/null | grep -EiC1 'usb .*(error|descriptor|enumerate)|uvcvideo|over.?current' | tail -60 \
    || echo "(dmesg needs root; rerun with sudo)"
fi

say "Overcurrent"
{ journalctl -k -b --no-pager 2>/dev/null || dmesg 2>/dev/null; } \
  | grep -Ei 'over.?current' || echo "none reported"

say "Ports reporting a connection with no working device"
for d in /sys/bus/usb/devices/*/; do
  [ -r "$d/idVendor" ] || continue
  printf '%s %s:%s %s\n' "$(basename "$d")" \
    "$(cat "$d/idVendor" 2>/dev/null)" "$(cat "$d/idProduct" 2>/dev/null)" \
    "$(cat "$d/product" 2>/dev/null || echo '-')"
done

say "irlume state"
command -v irlume >/dev/null 2>&1 && irlume version 2>&1 || echo "irlume not on PATH"
for f in /var/lib/irlume/ir_emitter.conf /etc/irlume/cameras.conf; do
  if [ -r "$f" ]; then echo "--- $f ---"; cat "$f"; fi
done

say "How to read this"
cat <<'EOF'
  camera enumerates normally      it is answering again; stop experimenting
  an unfamiliar new USB device     report it, write nothing to it
  repeated descriptor -110        port sees it electrically; it will not answer
  no camera event at all          power, cable, or the port is disabled
  overcurrent reported            stop power-cycling; report it

What is worth trying, once, in this order:
  1. Shut down. Disconnect AC and every peripheral.
  2. Use the emergency-reset hole as described in the Lenovo user guide.
  3. Reconnect AC and boot straight into UEFI setup. Check Security > I/O Port
     Access > Integrated Camera is Enabled if that setting is present.
  4. Boot normally and re-run this script before opening any camera app.

That is the whole safe procedure. Lenovo does not document the reset hole as
removing power from the camera specifically, so this may not help, but it is the
least invasive documented reset and it costs nothing.

Do NOT do any of these:
  - send further UVC extension-unit writes of any kind
  - install any camera firmware image, or a vendor updater not published by
    Lenovo for THIS machine. Such tools expect a firmware binary matched to a
    specific product ID and controller, and neither is established here
  - write to the USB `authorized` flag, unbind the xHCI controller, or cycle hub
    ports with uhubctl. None of these can repair firmware state, and they can
    disturb the keyboard, storage, Bluetooth or the fingerprint reader
  - buy a replacement camera from a part number found online. This machine ships
    in three camera configurations (5MP, 5MP+IR, 5MP+IR with presence
    detection). Resolve the part from your serial through Lenovo Parts Lookup
    and verify it against the FRU printed on the installed module

What is NOT yet established, and matters:

  The camera not enumerating tells you the host stopped getting answers. It does
  NOT tell you which part failed. Before anything is replaced, a technician
  should check the camera cable and its connectors at both ends, cable
  continuity, the camera power rail, and the system-board camera connector, and
  should try a known-good module on the same connection. If a known-good module
  also fails there, the cable, connector or system board is the stronger
  suspect, not the camera.

  Ask that the original module is not discarded, and ask for the findings in
  writing saying which component failed. If you claim under warranty, ask for
  the decision in writing too.

As of 29 July 2026 we searched for and did not find any public recovery
procedure, recovery USB ID, fwupd or LVFS entry, or Lenovo firmware package for
174f:11b4. That is a search result, not proof none exists. What is certain is
narrower: until the device enumerates, ordinary UVC requests cannot be issued to
it at all, so nothing at the camera-software level can reach it.

On repair: Lenovo does list the camera-and-microphone module and cable in its
Self-Repair guidance, so this is not a sealed assembly, and the whole lid should
not need replacing. Reaching it is still an extensive display disassembly:
base cover, I/O bracket, LCD unit, bezel, hinges, and an adhesively retained LCD
panel. If the machine is under warranty, service is the sensible route, and in
some jurisdictions using independent repair does not by itself void a warranty
even if damage attributed to it can be excluded. Check your local position.

Keep everything this script printed. Also record your machine serial and full
model type, BIOS version, and the kernel journal from the boot where the camera
was last working. Parts and coverage are both configuration-specific.
EOF

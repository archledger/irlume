#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Report camera capture timings from legacy irlume daemon debug logs.

New investigations should record a bounded structured trace with `sudo irlume
trace` and inspect it with `irlume trace explain`. This parser remains for old
journal captures and compatibility with `irlume logs debug on`; the lines it
parses look like:

    irlume[debug]: assess: rgb 640x480 in 704ms, faces=1 top-det=0.93
    irlume[debug]: assess: ir 640x400 in 1071ms, faces=1 top-det=0.93

Usage:
    journalctl -u irlumed --since -1h > /tmp/irlume.log
    scripts/timing-report.py /tmp/irlume.log

Prints per-side count/min/avg/max, then pairs each verify's rgb+ir and
reports the average overlapped capture cost (max of each pair, used when the
stored or explicit capture mode is concurrent) versus sequential (sum of each
pair).
If one side has more samples than the other (e.g. a failed capture),
the unpaired tail is dropped from the pair stats and a note is printed.
"""
import re
import sys


def analyze_log(log_path):
    rgb_times = []
    ir_times = []
    try:
        log_file = open(log_path, "r")
    except OSError as err:
        print(f"cannot read {log_path}: {err.strerror}", file=sys.stderr)
        return 1
    with log_file:
        for line in log_file:
            if "assess: rgb" in line:
                match = re.search(r"in (\d+)ms", line)
                if match:
                    rgb_times.append(int(match.group(1)))
            elif "assess: ir" in line:
                match = re.search(r"in (\d+)ms", line)
                if match:
                    ir_times.append(int(match.group(1)))

    if not rgb_times and not ir_times:
        print("no 'assess: rgb/ir ... in Nms' lines found; is debug tracing on?")
        print("enable with: sudo irlume logs debug on")
        return 1

    for name, times in (("RGB", rgb_times), ("IR", ir_times)):
        if times:
            print(
                f"{name}: count={len(times)}, min={min(times)}ms, "
                f"avg={sum(times) / len(times):.2f}ms, max={max(times)}ms"
            )
        else:
            print(f"{name}: no samples")

    if len(rgb_times) != len(ir_times):
        print(
            f"note: {len(rgb_times)} rgb vs {len(ir_times)} ir samples; "
            "unpaired tail dropped from pair stats"
        )

    overlaps = []
    sequentials = []
    for rgb_time, ir_time in zip(rgb_times, ir_times):
        overlaps.append(max(rgb_time, ir_time))
        sequentials.append(rgb_time + ir_time)
        print(
            f"pair: rgb={rgb_time}ms ir={ir_time}ms -> "
            f"overlap={overlaps[-1]}ms sequential={sequentials[-1]}ms"
        )

    if overlaps:
        print(f"average overlap:    {sum(overlaps) / len(overlaps):.2f}ms")
        print(f"average sequential: {sum(sequentials) / len(sequentials):.2f}ms")
        return 0
    # This report exists to compare RGB against IR, and zip() over an empty
    # side iterates zero times, so a log with samples from only one spectrum
    # produced no pair at all and still exited 0. The earlier guard used AND, so
    # it only caught a log with nothing in it. Producing no pair statistics is
    # the failure this is asked to detect, whichever side is missing.
    print(
        f"no pairs to compare: {len(rgb_times)} rgb and {len(ir_times)} ir samples, "
        "so no overlap or sequential figure was produced",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: timing-report.py <log-file>", file=sys.stderr)
        sys.exit(2)
    sys.exit(analyze_log(sys.argv[1]))

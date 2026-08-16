#!/usr/bin/env python3
"""Validate structured evidence from slice-4 physical timestamp stress tests."""

import json
import math
import pathlib
import sys
from typing import NoReturn

U64_MAX = (1 << 64) - 1
U32_MAX = (1 << 32) - 1
I64_MAX = (1 << 63) - 1
MIN_CONTINUITY_HZ = 1.0
MAX_CONTINUITY_DELTA_US = 1_000_000
TIMESTAMP_BOUNDARY_INTERVALS = 3
# The global timestamp span (first delivered frame to last) may legitimately
# undershoot the measured duration by the capture loop's start and end slack:
# the first frame lands up to ~one interval after the loop starts, and the last
# frame of the slower stream in a concurrent pair lands up to ~three intervals
# before the loop's deadline (measured ~201 ms of end lag on the ASUS IR at
# 15 fps). A real stall collapses the span by whole seconds, so a separate,
# wider budget here keeps that signal while not flaking on clean timing.
GLOBAL_SPAN_BOUNDARY_INTERVALS = 6
RECORD_KEYS = {
    "kind",
    "schema_version",
    "host",
    "commit",
    "requested_duration_seconds",
    "duration_seconds",
    "recovery_exercised",
    "recovery_duration_seconds",
    "rgb_ir_skew_us",
    "streams",
}
STREAM_KEYS = {
    "role",
    "frames",
    "observations",
    "discarded_observations",
    "sequence_span_sum",
    "delivered_hz",
    "gap_total",
    "cumulative_drops",
    "discontinuities",
    "epoch_count",
    "timestamp_span_sum_us",
    "delta_count",
    "delta_sum_us",
    "delta_min_us",
    "delta_max_us",
    "clock",
    "source",
    "stream_epoch",
    "sequence_stream_epoch",
    "timestamp_stream_epoch",
    "first_timestamp_us",
    "last_timestamp_us",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def reject_nonstandard_constant(value):
    fail(f"non-standard JSON numeric constant: {value}")


def bounded_u64(value, label):
    if type(value) is not int or not 0 <= value <= U64_MAX:
        fail(f"{label}: expected a nonnegative u64, got {value!r}")
    return value


def positive_u64(value, label):
    value = bounded_u64(value, label)
    if value == 0:
        fail(f"{label}: expected a positive integer")
    return value


def finite_number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label}: expected a finite number, got {value!r}")
    if not math.isfinite(value):
        fail(f"{label}: expected a finite number, got {value!r}")
    return value


def main(argv):
    if len(argv) != 5:
        fail("usage: validate LOG EXPECTED_HOST EXPECTED_SHA EXPECTED_STREAMS")

    log_path, expected_host, expected_sha, expected_streams_raw = argv[1:]
    try:
        expected_streams = int(expected_streams_raw)
    except ValueError as error:
        fail(f"invalid expected stream count: {error}")
    if expected_streams not in {1, 2}:
        fail(f"expected stream count must be 1 or 2, got {expected_streams}")

    records = []
    for raw in pathlib.Path(log_path).read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            record = json.loads(
                raw,
                object_pairs_hook=reject_duplicate_members,
                parse_constant=reject_nonstandard_constant,
            )
        except json.JSONDecodeError as error:
            fail(f"malformed JSON candidate: {error}")
        if isinstance(record, dict) and record.get("kind") == "irlume.slice4.hardware":
            records.append(record)

    if len(records) != 1:
        fail(f"expected exactly one slice-4 evidence record, got {len(records)}")
    record = records[0]
    if set(record) != RECORD_KEYS:
        fail(f"unexpected evidence keys: {sorted(record)}")
    schema_version = bounded_u64(record.get("schema_version"), "schema version")
    if schema_version != 1:
        fail(f"unsupported evidence schema version: {schema_version}")
    if record.get("host") != expected_host:
        fail(f"host mismatch: {record.get('host')!r} != {expected_host!r}")
    if record.get("commit") != expected_sha:
        fail(f"commit mismatch: {record.get('commit')!r} != {expected_sha!r}")
    if record.get("recovery_exercised") is not True:
        fail("recovery was not exercised")

    requested = bounded_u64(record.get("requested_duration_seconds"), "requested duration")
    if not 60 <= requested <= 600:
        fail(f"invalid requested duration: {requested!r}")
    duration = finite_number(record.get("duration_seconds"), "measured duration")
    if duration < requested or duration > requested + 30:
        fail(f"invalid measured duration: {duration!r}")
    recovery_duration = finite_number(
        record.get("recovery_duration_seconds"), "recovery duration"
    )
    if recovery_duration <= 0 or recovery_duration > duration - requested / 2:
        fail(f"invalid recovery duration: {recovery_duration!r}")

    streams = record.get("streams")
    if not isinstance(streams, list) or len(streams) != expected_streams:
        fail(f"expected {expected_streams} stream records, got {streams!r}")
    if not all(isinstance(stream, dict) for stream in streams):
        fail("every stream record must be an object")
    expected_roles = ["rgb"] if expected_streams == 1 else ["rgb", "ir"]
    if [stream.get("role") for stream in streams] != expected_roles:
        fail(f"unexpected stream roles: {streams!r}")

    last_timestamps = {}
    for stream in streams:
        role = stream["role"]
        if set(stream) != STREAM_KEYS:
            fail(f"{role}: unexpected stream keys: {sorted(stream)}")
        frames = positive_u64(stream.get("frames"), f"{role}: frames")
        if frames < 2:
            fail(f"{role}: insufficient frames")
        observations = positive_u64(stream.get("observations"), f"{role}: observations")
        discarded_observations = bounded_u64(
            stream.get("discarded_observations"), f"{role}: discarded observations"
        )
        # The delivered-rate fill discards a bounded number of frames per
        # stream on top of the warm-up discards: flush RATE_STARTUP_FLUSH (30)
        # + fill (1 seed + RATE_WINDOW_CAPACITY deltas = 31) per establishment,
        # run twice (initial + post-recovery). The faster stream keeps
        # discarding until its slower twin is ready, so the total is rate-ratio
        # dependent; assert only the deterministic minimum, and let the
        # delivered/discarded accounting check above catch inconsistency.
        minimum_discarded = {
            # warm-up (14 = 7 initial + 7 recovered; 1 = the IR session warm-up)
            # + two fill establishments (2 * 61).
            "rgb": 14 + 2 * 61,
            "ir": 1 + 2 * 61,
        }[role]
        if discarded_observations < minimum_discarded:
            fail(
                f"{role}: discarded observations {discarded_observations} below "
                f"the minimum fill/warm-up {minimum_discarded}"
            )
        if observations != frames + discarded_observations:
            fail(f"{role}: delivered/discarded observation accounting mismatch")
        sequence_span_sum = positive_u64(
            stream.get("sequence_span_sum"), f"{role}: sequence span sum"
        )
        delivered = finite_number(stream.get("delivered_hz"), f"{role}: delivered rate")
        expected_rate = frames / duration
        if not math.isclose(delivered, expected_rate, rel_tol=1e-12, abs_tol=1e-12):
            fail(
                f"{role}: delivered rate {delivered!r} does not match "
                f"{frames}/{duration}={expected_rate!r}"
            )
        if delivered < MIN_CONTINUITY_HZ:
            fail(
                f"{role}: delivered rate {delivered!r} is below the "
                f"{MIN_CONTINUITY_HZ:g} Hz continuity-evidence floor"
            )
        gap_total = bounded_u64(stream.get("gap_total"), f"{role}: gap total")
        cumulative_drops = bounded_u64(
            stream.get("cumulative_drops"), f"{role}: cumulative drops"
        )
        if cumulative_drops != gap_total:
            fail(
                f"{role}: cumulative drops {cumulative_drops} do not equal "
                f"all observed gaps {gap_total}"
            )
        if cumulative_drops > U32_MAX:
            fail(f"{role}: drops exceed one full 32-bit sequence space")
        if stream.get("clock") != "Monotonic":
            fail(f"{role}: untrusted clock {stream.get('clock')!r}")
        if stream.get("source") not in {"EndOfFrame", "StartOfExposure"}:
            fail(f"{role}: untrusted source {stream.get('source')!r}")
        epoch = bounded_u64(stream.get("stream_epoch"), f"{role}: stream epoch")
        sequence_epoch = bounded_u64(
            stream.get("sequence_stream_epoch"), f"{role}: sequence stream epoch"
        )
        timestamp_epoch = bounded_u64(
            stream.get("timestamp_stream_epoch"), f"{role}: timestamp stream epoch"
        )
        if epoch != 1 or sequence_epoch != epoch or timestamp_epoch != epoch:
            fail(
                f"{role}: expected one aligned recovered epoch, got "
                f"{sequence_epoch!r}/{timestamp_epoch!r}/{epoch!r}"
            )
        discontinuities = bounded_u64(
            stream.get("discontinuities"), f"{role}: discontinuities"
        )
        if discontinuities != 1:
            fail(f"{role}: expected exactly one recovery discontinuity")
        epoch_count = positive_u64(stream.get("epoch_count"), f"{role}: epoch count")
        if epoch_count != epoch + 1 or epoch_count != discontinuities + 1:
            fail(f"{role}: epoch count is incoherent")
        expected_sequence_span = observations - epoch_count + cumulative_drops
        if sequence_span_sum != expected_sequence_span:
            fail(
                f"{role}: sequence span {sequence_span_sum} does not equal "
                f"observations - epochs + drops ({expected_sequence_span})"
            )
        timestamp_span_sum = positive_u64(
            stream.get("timestamp_span_sum_us"), f"{role}: timestamp span sum"
        )
        delta_count = positive_u64(stream.get("delta_count"), f"{role}: delta count")
        if delta_count != frames - epoch_count:
            fail(f"{role}: delta count does not equal frames minus epochs")
        delta_sum = positive_u64(stream.get("delta_sum_us"), f"{role}: delta sum")
        if delta_sum != timestamp_span_sum:
            fail(f"{role}: delta sum does not equal per-epoch timestamp spans")
        minimum = positive_u64(stream.get("delta_min_us"), f"{role}: minimum delta")
        maximum = positive_u64(stream.get("delta_max_us"), f"{role}: maximum delta")
        if maximum < minimum:
            fail(f"{role}: invalid timestamp deltas {minimum!r}..{maximum!r}")
        if delta_count == 1:
            minimum_sum = maximum_sum = minimum
            if maximum != minimum:
                fail(f"{role}: one delta cannot have distinct extrema")
        else:
            minimum_sum = maximum + minimum * (delta_count - 1)
            maximum_sum = minimum + maximum * (delta_count - 1)
        if not minimum_sum <= delta_sum <= maximum_sum:
            fail(
                f"{role}: delta sum {delta_sum} is outside extrema-derived "
                f"bounds {minimum_sum}..{maximum_sum}"
            )
        if maximum > MAX_CONTINUITY_DELTA_US:
            fail(
                f"{role}: maximum timestamp delta {maximum}us exceeds the "
                f"{MAX_CONTINUITY_DELTA_US}us continuity-evidence ceiling"
            )
        first_timestamp = positive_u64(
            stream.get("first_timestamp_us"), f"{role}: first timestamp"
        )
        last_timestamp = positive_u64(
            stream.get("last_timestamp_us"), f"{role}: last timestamp"
        )
        if first_timestamp > I64_MAX or last_timestamp > I64_MAX:
            fail(f"{role}: timestamp exceeds signed producer domain")
        if last_timestamp <= first_timestamp:
            fail(
                f"{role}: timestamps did not advance: "
                f"{first_timestamp}..{last_timestamp}"
            )
        timestamp_span = last_timestamp - first_timestamp
        if timestamp_span_sum > timestamp_span:
            fail(f"{role}: per-epoch spans exceed the global timestamp span")
        omitted_span = timestamp_span - timestamp_span_sum
        recovery_duration_us = recovery_duration * 1_000_000
        if (
            abs(omitted_span - recovery_duration_us)
            > TIMESTAMP_BOUNDARY_INTERVALS * maximum
        ):
            fail(f"{role}: omitted timestamp span does not match recovery duration")
        duration_us = duration * 1_000_000
        if (
            abs(timestamp_span - duration_us)
            > GLOBAL_SPAN_BOUNDARY_INTERVALS * maximum
        ):
            fail(
                f"{role}: global timestamp span {timestamp_span}us does not track "
                f"measured duration {duration_us}us"
            )
        last_timestamps[role] = last_timestamp

    if expected_streams == 2:
        skew = bounded_u64(record.get("rgb_ir_skew_us"), "RGB/IR skew")
        expected_skew = abs(last_timestamps["rgb"] - last_timestamps["ir"])
        if skew != expected_skew:
            fail(f"RGB/IR skew mismatch: {skew} != {expected_skew}")
    elif record.get("rgb_ir_skew_us") is not None:
        fail("RGB-only run unexpectedly reported RGB/IR skew")

    print(json.dumps(record, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main(sys.argv)

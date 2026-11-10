# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Closed, metadata-only contract for the production-request evaluator."""

from pathlib import Path

CAUSES = frozenset(
    {
        "invalid_request",
        "root_required",
        "models_unavailable",
        "state_unavailable",
        "state_requires_repair",
        "state_changed",
        "no_face",
        "liveness_refused",
        "identity_mismatch",
        "camera_unavailable",
        "setup_unavailable",
        "policy",
        "cancelled",
        "deadline_expired",
        "runtime_unavailable",
    }
)
COUNTS = ("assessments", "captures", "detections", "pad", "identity")
TIMINGS = ("load", "capture", "detection", "pad", "identity")


def checked_report(record):
    if not isinstance(record, dict) or record.keys() != {
        "schema",
        "operation",
        "phase",
        "authentication_granted",
        "result",
        "scope",
        "window_ms",
        "elapsed_ms",
        "initialization_ms",
        "counts",
        "timings_ms",
    }:
        raise ValueError("invalid_request_report")
    if (
        type(record["schema"]) is not int
        or record["schema"] != 1
        or record["operation"] != "ir_request_evaluation"
        or record["authentication_granted"] is not False
        or record["phase"] not in ("preflight", "evaluation")
        or record["scope"] not in (None, "primary", "secondary")
    ):
        raise ValueError("invalid_request_report")
    for key in ("window_ms", "elapsed_ms"):
        if type(record[key]) is not int or not 0 <= record[key] <= 120_000:
            raise ValueError("invalid_request_timing")
    initialization = record["initialization_ms"]
    if initialization is not None and (
        type(initialization) is not int or not 0 <= initialization <= 120_000
    ):
        raise ValueError("invalid_request_timing")
    counts, timings, result = record["counts"], record["timings_ms"], record["result"]
    if not isinstance(counts, dict) or counts.keys() != set(COUNTS):
        raise ValueError("invalid_request_counts")
    values = [counts[key] for key in COUNTS]
    if any(
        type(v) is not int or not 0 <= v <= 1_000_000 for v in values
    ) or values != sorted(values, reverse=True):
        raise ValueError("invalid_request_counts")
    if not isinstance(timings, dict) or timings.keys() != set(TIMINGS):
        raise ValueError("invalid_request_timing")
    if any(
        v is not None and (type(v) is not int or not 0 <= v <= 120_000)
        for v in timings.values()
    ):
        raise ValueError("invalid_request_timing")
    if not isinstance(result, dict):
        raise TypeError("invalid_request_result")
    kind = result.get("kind")
    if kind == "ready":
        valid = (
            result.keys() == {"kind"}
            and record["phase"] == "preflight"
            and values == [0] * 5
            and record["scope"] is not None
            and record["window_ms"] > 0
        )
    elif kind == "would_grant":
        valid = (
            result.keys() == {"kind", "identity_acceptance"}
            and record["phase"] == "evaluation"
            and result["identity_acceptance"] in ("best_template", "centroid", "both")
            and values[-1] > 0
            and record["scope"] is not None
            and record["window_ms"] > 0
        )
    elif kind == "refused":
        valid = (
            result.keys() == {"kind", "cause"}
            and isinstance(result["cause"], str)
            and result["cause"] in CAUSES
        )
    elif kind == "incomplete":
        valid = result.keys() == {"kind", "cause"} and result["cause"] in (
            "missing_evidence",
            "measurement_overflow",
        )
    else:
        valid = False
    if not valid:
        raise ValueError("invalid_request_result")
    for count, timing in zip(COUNTS[1:], TIMINGS[1:]):
        if (
            counts[count] == 0
            and timings[timing] is not None
            or counts[count] > 0
            and timings[timing] is None
            and kind != "incomplete"
        ):
            raise ValueError("inconsistent_request_measurement")
    if record["phase"] == "preflight" and values != [0] * 5:
        raise ValueError("preflight_captured")
    return record


def qualified_topology(nodes, cameras, members):
    """Match the production separate-interface or exact four-node shared layout."""
    ir, rgb = nodes["ir"], nodes["rgb"]
    meta = nodes.get("metadata")
    if (
        rgb["index"] != 0
        or not members
        or any(
            "/virtual/" in node["interface"]
            for node in [*nodes.values(), *members.values()]
        )
    ):
        return False
    if len({node["device"] for node in members.values()}) != len(members):
        return False
    if any(node["interface"] != ir["interface"] for node in members.values()):
        return False
    if members.get(Path(cameras["ir"]).name) != ir:
        return False
    if ir["interface"] != rgb["interface"]:
        expected = {Path(cameras["ir"]).name}
        if meta is not None:
            expected.add(Path(cameras["metadata"]).name)
        return (
            ir["index"] == 0
            and members.keys() == expected
            and (
                meta is None
                or (
                    meta["index"] == 1
                    and meta["name"] == ir["name"]
                    and members.get(Path(cameras["metadata"]).name) == meta
                )
            )
        )
    ordered = sorted(members.items(), key=lambda pair: pair[1]["index"])
    if len(ordered) != 4 or [node["index"] for _, node in ordered] != [0, 1, 2, 3]:
        return False
    return (
        ordered[0] == (Path(cameras["rgb"]).name, rgb)
        and ordered[2] == (Path(cameras["ir"]).name, ir)
        and meta is not None
        and ordered[3] == (Path(cameras["metadata"]).name, meta)
        and ordered[1][1]["name"] == rgb["name"]
        and meta["name"] == ir["name"]
    )

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
"""Pure private runtime-report contracts. No process or native execution.

Decoded records are candidate observations, never an authenticated run or case
qualification. The future collector must independently enforce provenance,
deadlines, finalization and native positive/mutant controls. Replaying this pure
function is possible; replay prevention across invocations belongs to that owner.
"""

import json
import re
from types import MappingProxyType
from typing import NamedTuple

MAX_FRAME = 16 * 1024
U64_MAX = 2**64 - 1
U32_MAX = 2**32 - 1
LIMITS = MappingProxyType(
    {
        "case_total_ns": 20_000_000_000,
        "phase_ns": 5_000_000_000,
        "case_output_bytes": 1_048_576,
        "max_operations": 8192,
        "batch_cases": 6,
    }
)


class Identity(NamedTuple):
    run_id: str
    boot_input_sha256: str
    guest_boot_id: str
    build_sha256: str
    input_manifest_sha256: str


class Expected(NamedTuple):
    """Out-of-band selection; none of these expectations comes from a report."""

    identity: Identity
    first_epoch: int
    cases: tuple


class Observation(NamedTuple):
    """Immutable original bytes plus a policy match, not a runtime verdict."""

    frame: bytes
    case: str
    epoch: int
    sequence: int
    outcome: str
    cleanup: str
    matches_expected: bool
    accepted: bool = False
    native_authorized: bool = False
    full_contract_proven: bool = False


class Batch(NamedTuple):
    observations: tuple
    cases: tuple
    matches_expected: bool
    full_inventory: bool
    accepted: bool = False
    native_authorized: bool = False
    full_contract_proven: bool = False


CASES = (
    "supervisor-only",
    "loss-before-birth",
    "loss-before-delivery",
    "loss-before-registration",
    "loss-before-placement",
    "loss-before-readback",
    "loss-after-readback",
    "double-fork",
    "zombie",
    "bounds-complete",
    "bounds-supervisor-stall",
    "bounds-worker-stall",
    "bounds-extension-flood",
    "bounds-output-flood",
    "bounds-replay",
    "bounds-late-read",
    "bounds-pre-cutover-loss",
    "bounds-withheld-wait",
    "bounds-withheld-population",
    "bounds-withheld-consumer",
    "bounds-withheld-sentinel",
)


def expected_outcome(case):
    """Fixed policy, independent of a received report or caller-supplied verdict."""
    if type(case) is not str or case not in CASES:
        raise ValueError("unknown case")
    if case in ("supervisor-only", "bounds-complete"):
        return "complete"
    if case in (
        "bounds-withheld-wait",
        "bounds-withheld-population",
        "bounds-withheld-consumer",
        "bounds-withheld-sentinel",
    ):
        return "incomplete"
    return "aborted_clean"


def _fields(row, names):
    if type(row) is not dict or set(row) != set(names):
        raise ValueError("invalid fields")


def _integer(value, low=0, high=U64_MAX):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid integer")


def _boolean(value):
    if type(value) is not bool:
        raise ValueError("invalid boolean")


def _array(value, count, check):
    if type(value) is not list or len(value) != count:
        raise ValueError("invalid array")
    for item in value:
        check(item)


def _optional(value, check):
    if value is not None:
        check(value)


def _identifier(value):
    if (
        type(value) is not str
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value) is None
    ):
        raise ValueError("invalid identifier")


def _identity(value):
    if type(value) is not Identity:
        raise ValueError("separate identity required")
    _identifier(value.run_id)
    for digest in (
        value.boot_input_sha256,
        value.build_sha256,
        value.input_manifest_sha256,
    ):
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("invalid digest")
    if (
        type(value.guest_boot_id) is not str
        or re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value.guest_boot_id
        )
        is None
    ):
        raise ValueError("invalid guest boot identity")


def _expected(want):
    if type(want) is not Expected:
        raise ValueError("separate expectations required")
    _identity(want.identity)
    if (
        type(want.cases) is not tuple
        or not 1 <= len(want.cases) <= LIMITS["batch_cases"]
    ):
        raise ValueError("invalid batch")
    for case in want.cases:
        expected_outcome(case)
    if len(set(want.cases)) != len(want.cases):
        raise ValueError("duplicate selected case")
    _integer(want.first_epoch, 1, U64_MAX - len(want.cases) + 1)


def _failure(value):
    if value is None:
        return
    _fields(value, ("operation", "errno"))
    _identifier(value["operation"])
    _integer(value["errno"], 0, 2**31 - 1)


def _wait(value):
    if value is None:
        return
    _fields(value, ("pid", "code", "status"))
    _integer(value["pid"], 1, 2**31 - 1)
    _integer(value["code"], 1, 3)
    _integer(
        value["status"],
        0 if value["code"] == 1 else 1,
        255 if value["code"] == 1 else 64,
    )


_REPORT_FLAGS = (
    "injected",
    "registered",
    "placed",
    "placement_verified",
    "worker_reaped",
    "descendant_reaped",
    "reserved",
    "custody_retained",
    "errors_truncated",
    "kill",
    "empty",
    "direct_reaped",
    "drained",
    "native_authorized",
    "full_contract_proven",
)
_REPORT_INTS = ("oom_observations", "releases", "consumers", "operations")
_BOUNDS_FLAGS = (
    "active",
    "candidate_received",
    "result_postcheck_pending",
    "result_valid",
    "worker_terminal",
    "cutover",
    "loss_observed",
    "stopped_oom_checked",
    "sentinel_created",
    "sentinel_pre",
    "sentinel_post",
    "sentinel_stopped",
    "sentinel_failed",
    "consumer_withheld",
)
_CUTS = (
    "before-birth",
    "before-delivery",
    "before-registration",
    "before-placement",
    "before-readback",
    "after-readback",
)


def _bounds(row):
    _fields(
        row,
        (
            *_BOUNDS_FLAGS,
            "output",
            "work_cap",
            "caps",
            "result_frame",
            "result_return",
            "replay_epoch",
        ),
    )
    for key in _BOUNDS_FLAGS:
        _boolean(row[key])
    _fields(row["output"], ("bytes", "exhausted"))
    _integer(row["output"]["bytes"])
    _boolean(row["output"]["exhausted"])
    _integer(row["work_cap"])
    _array(row["caps"], 4, _integer)
    _optional(row["result_return"], _integer)
    _optional(row["replay_epoch"], lambda v: _integer(v, 1))
    _optional(
        row["result_frame"], lambda v: _array(v, 9, lambda byte: _integer(byte, 0, 255))
    )


def _report(row, completion):
    _fields(
        row,
        (
            *_REPORT_FLAGS,
            *_REPORT_INTS,
            "bounds",
            "case",
            "reached",
            "worker_pid",
            "descendant_pid",
            "oom_kills",
            "epoch",
            "outcome",
            "leases_held",
            "first",
            "errors",
            "adopted",
            "terminal",
        ),
    )
    expected_outcome(row["case"])
    if row["reached"] is not None and row["reached"] not in _CUTS:
        raise ValueError("invalid cut")
    for key in _REPORT_FLAGS:
        _boolean(row[key])
    for key in _REPORT_INTS:
        _integer(row[key], 0, U32_MAX)
    for key in ("worker_pid", "descendant_pid"):
        _optional(row[key], lambda v: _integer(v, 1, 2**31 - 1))
    _integer(row["epoch"], 1)
    _integer(row["adopted"], 0, 32)
    _array(row["oom_kills"], 3, _integer)
    _array(row["leases_held"], 2, _boolean)
    _failure(row["first"])
    _array(row["errors"], 16, _failure)
    _array(row["terminal"], 33, _wait)
    if row["outcome"] not in (
        "complete",
        "aborted_clean",
        "no_job_created",
        "incomplete",
    ):
        raise ValueError("invalid outcome")
    if completion not in ("clean", "quarantined") or (
        row["outcome"] == "incomplete"
    ) != (completion == "quarantined"):
        raise ValueError("completion/outcome mismatch")
    if row["native_authorized"] or row["full_contract_proven"]:
        raise ValueError("authority claim")
    if row["outcome"] == "no_job_created" and (
        any(
            row[key]
            for key in (
                "kill",
                "empty",
                "direct_reaped",
                "drained",
                "worker_reaped",
                "descendant_reaped",
                "consumers",
                "adopted",
            )
        )
        or row["worker_pid"] is not None
        or row["descendant_pid"] is not None
        or any(value is not None for value in row["terminal"])
        or row["releases"] != 1
        or row["leases_held"] != [False, False]
        or row["custody_retained"]
    ):
        raise ValueError("no-job record claims acquired job ownership")
    if row["case"].startswith("bounds-"):
        _bounds(row["bounds"])
    elif row["bounds"] is not None:
        raise ValueError("unexpected bounds record")


def _clean(r):
    return (
        r["kill"]
        and r["empty"]
        and r["direct_reaped"]
        and r["drained"]
        and r["consumers"] == 0
        and r["releases"] == 1
        and r["leases_held"] == [False, False]
        and not r["custody_retained"]
    )


def _terminals_match(r):
    entries = r["terminal"]
    if bool(entries[0]) != r["direct_reaped"]:
        return False
    adopted = entries[1 : 1 + r["adopted"]]
    if any(x is None for x in adopted) or any(
        x is not None for x in entries[1 + r["adopted"] :]
    ):
        return False
    pids = [x["pid"] for x in entries if x is not None]
    if len(set(pids)) != len(pids):
        return False
    known = [r[key] for key in ("worker_pid", "descendant_pid") if r[key] is not None]
    if len(set(known)) != len(known) or any(x["pid"] not in known for x in adopted):
        return False
    for name in ("worker", "descendant"):
        found = [x for x in adopted if x["pid"] == r[name + "_pid"]]
        if bool(found) != r[name + "_reaped"]:
            return False
        if (
            name == "worker"
            and found
            and r["bounds"]
            and r["bounds"]["cutover"]
            and (found[0]["code"] != 1 or found[0]["status"] != 0)
        ):
            return False
    return True


def _roles_match(r):
    supervisor = r["terminal"][0]
    if supervisor is None:
        return False
    worker = r["worker_pid"]
    descendant = r["descendant_pid"]
    needs_worker = r["case"] not in ("supervisor-only", "loss-before-birth")
    if (worker is not None) != needs_worker or (descendant is not None) != (
        r["case"] == "double-fork"
    ):
        return False
    pids = [
        supervisor["pid"],
        *([worker] if worker is not None else []),
        *([descendant] if descendant is not None else []),
    ]
    return len(pids) == len(set(pids))


def _supervisor_killed(r):
    event = r["terminal"][0]
    return event is not None and event["code"] == 2 and event["status"] == 9


def _result_consistent(r):
    """Relate raw result observations to bounds.rs's reached producer stage."""
    s = r["bounds"]
    case = r["case"]
    raw = s["result_frame"]
    returned = s["result_return"]
    if s["result_postcheck_pending"] or not s["sentinel_created"]:
        return False
    if case != "bounds-replay" and s["replay_epoch"] is not None:
        return False
    if not s["worker_terminal"] and (s["stopped_oom_checked"] or s["sentinel_stopped"]):
        return False
    if case in ("bounds-complete", "bounds-pre-cutover-loss", *CASES[17:]):
        return (
            s["result_valid"]
            and s["candidate_received"]
            and s["worker_terminal"]
            and raw == [2, *r["epoch"].to_bytes(8, "little")]
            and s["work_cap"] > 0
            and returned is not None
            and returned < s["work_cap"]
        )
    if case == "bounds-late-read":
        return (
            not s["result_valid"]
            and not s["worker_terminal"]
            and s["candidate_received"]
            and raw == [2, *r["epoch"].to_bytes(8, "little")]
            and s["work_cap"] > 0
            and returned is not None
            and returned >= s["work_cap"]
        )
    if (
        s["result_valid"]
        or s["worker_terminal"]
        or s["candidate_received"]
        or returned is not None
    ):
        return False
    if case in ("bounds-supervisor-stall", "bounds-worker-stall"):
        return raw is None
    if case == "bounds-replay":
        epoch = s["replay_epoch"]
        return (
            epoch is not None
            and epoch != r["epoch"]
            and raw == [2, *epoch.to_bytes(8, "little")]
        )
    if case in ("bounds-extension-flood", "bounds-output-flood"):
        first = r["first"]["operation"] if r["first"] else None
        if first == "bounds-result-record":
            return raw is not None and (
                raw[0] != 2 or int.from_bytes(bytes(raw[1:]), "little") == 0
            )
        return first in ("channel-surplus", "output-cap") and raw is None
    return False


def _matches(r):
    case = r["case"]
    errors = [x for x in r["errors"] if x is not None]
    if (
        r["outcome"] != expected_outcome(case)
        or not r["reserved"]
        or r["errors_truncated"]
        or r["operations"] > LIMITS["max_operations"]
        or not _terminals_match(r)
        or not _roles_match(r)
        or r["errors"] != errors + [None] * (16 - len(errors))
        or r["first"] != (errors[0] if errors else None)
        or len({(e["operation"], e["errno"]) for e in errors}) != len(errors)
    ):
        return False
    if case == "supervisor-only":
        return (
            _clean(r)
            and not errors
            and r["adopted"] == 0
            and r["worker_pid"] is None
            and r["descendant_pid"] is None
        )
    if not case.startswith("bounds-"):
        cut = (
            case.removeprefix("loss-")
            if case.startswith("loss-")
            else "before-placement"
        )
        phase = _CUTS.index(cut)
        return (
            _clean(r)
            and r["reached"] == cut
            and r["injected"]
            and _supervisor_killed(r)
            and r["registered"] == (phase >= 3)
            and r["placed"] == (phase >= 4)
            and r["placement_verified"] == (phase == 5)
            and errors == [{"operation": "supervisor-loss-injected", "errno": 0}]
            and r["oom_observations"] == 3
            and r["oom_kills"] == [0, 0, 0]
            and r["adopted"]
            == (2 if case == "double-fork" else 0 if cut == "before-birth" else 1)
            and (r["worker_pid"] is None or r["worker_reaped"])
            and (r["descendant_pid"] is None or r["descendant_reaped"])
        )
    s = r["bounds"]
    if (
        not s["active"]
        or not s["sentinel_pre"]
        or s["sentinel_failed"]
        or r["oom_kills"] != [0, 0, 0]
        or any(error["errno"] != 0 for error in errors)
    ):
        return False
    if (
        not (r["registered"] and r["placed"] and r["placement_verified"])
        or r["reached"] is not None
        or r["injected"]
        or not _result_consistent(r)
    ):
        return False
    first = r["first"]["operation"] if r["first"] else None
    only = lambda allowed: all(e["operation"] in allowed for e in errors)
    clean = _clean(r) and r["worker_reaped"] and s["sentinel_post"]
    quarantined = (
        r["outcome"] == "incomplete"
        and r["releases"] == 0
        and r["leases_held"] == [True, True]
        and r["custody_retained"]
        and s["cutover"]
        and s["result_valid"]
        and s["worker_terminal"]
        and s["stopped_oom_checked"]
        and r["direct_reaped"]
    )
    if case == "bounds-complete":
        return (
            clean
            and s["cutover"]
            and s["result_valid"]
            and s["worker_terminal"]
            and first is None
        )
    if case in ("bounds-supervisor-stall", "bounds-worker-stall"):
        return (
            clean
            and not s["cutover"]
            and not s["result_valid"]
            and first == "expired"
            and only(("expired",))
        )
    if case in ("bounds-extension-flood", "bounds-output-flood"):
        allowed = ("bounds-result-record", "channel-surplus", "output-cap")
        return clean and not s["cutover"] and first in allowed and only(allowed)
    if case == "bounds-replay":
        return (
            clean
            and not s["cutover"]
            and first == "bounds-result-epoch"
            and only(("bounds-result-epoch",))
        )
    if case == "bounds-late-read":
        return clean and not s["cutover"] and first == "expired" and only(("expired",))
    if case == "bounds-pre-cutover-loss":
        return (
            clean
            and not s["cutover"]
            and s["loss_observed"]
            and _supervisor_killed(r)
            and s["result_valid"]
            and s["worker_terminal"]
            and first == "bounds-supervisor-loss"
            and only((first,))
        )
    if case == "bounds-withheld-wait":
        return (
            quarantined
            and s["sentinel_stopped"]
            and r["empty"]
            and not r["worker_reaped"]
            and not r["drained"]
            and r["consumers"] == 1
            and first == "fixture-withheld-wait"
            and only((first, "expired"))
        )
    if case == "bounds-withheld-population":
        return (
            quarantined
            and s["sentinel_stopped"]
            and not r["empty"]
            and r["worker_reaped"]
            and r["drained"]
            and r["consumers"] == 0
            and first == "fixture-withheld-population"
            and only((first, "expired"))
        )
    if case == "bounds-withheld-consumer":
        return (
            quarantined
            and s["sentinel_stopped"]
            and r["empty"]
            and r["worker_reaped"]
            and r["drained"]
            and r["consumers"] == 1
            and s["consumer_withheld"]
            and first == "expired"
            and only((first,))
        )
    if case == "bounds-withheld-sentinel":
        return (
            quarantined
            and r["empty"]
            and r["worker_reaped"]
            and r["drained"]
            and r["consumers"] == 0
            and not s["sentinel_post"]
            and first == "fixture-withheld-sentinel"
            and only((first,))
        )
    raise ValueError("missing case policy")


def _json(data):
    def pairs(items):
        row = {}
        for key, value in items:
            if key in row:
                raise ValueError("duplicate field")
            row[key] = value
        return row

    def integer(text):
        if len(text) > 20:
            raise ValueError("oversized integer")
        return int(text)

    def noninteger(_):
        raise ValueError("noninteger number")

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=noninteger,
            parse_constant=noninteger,
        )
    except (UnicodeError, RecursionError) as error:
        raise ValueError("invalid JSON") from error


def decode_report(data, want, sequence):
    """Validate one bounded candidate, without granting execution or qualification."""
    _expected(want)
    _integer(sequence, 0, len(want.cases) - 1)
    if type(data) is not bytes or not 4 < len(data) <= MAX_FRAME + 4:
        raise ValueError("invalid frame size/type")
    if int.from_bytes(data[:4], "big") != len(data) - 4:
        raise ValueError("invalid frame length")
    row = _json(data[4:])
    _fields(
        row, ("scope", "mode", "identity", "sequence", "limits", "completion", "report")
    )
    _fields(row["identity"], Identity._fields)
    _identity(Identity(**row["identity"]))
    _integer(row["sequence"], 0, LIMITS["batch_cases"] - 1)
    _fields(row["limits"], LIMITS)
    for key, value in LIMITS.items():
        _integer(row["limits"][key], value, value)
    if (
        row["scope"] != "contained-job-report-v1"
        or row["mode"] != "runtime-candidate"
        or row["identity"] != want.identity._asdict()
        or row["sequence"] != sequence
    ):
        raise ValueError("mismatched report context")
    r = row["report"]
    _report(r, row["completion"])
    if r["case"] != want.cases[sequence] or r["epoch"] != want.first_epoch + sequence:
        raise ValueError("mismatched case or epoch")
    cleanup = (
        "not-created"
        if r["outcome"] == "no_job_created"
        else "complete"
        if _clean(r)
        else "incomplete"
    )
    return Observation(
        data, r["case"], r["epoch"], sequence, r["outcome"], cleanup, _matches(r)
    )


def decode_batch(frames, want):
    """Require the entire selected batch; this cannot prove full native coverage."""
    _expected(want)
    if type(frames) is not tuple or len(frames) != len(want.cases):
        raise ValueError("incomplete or surplus batch")
    observations = tuple(decode_report(data, want, i) for i, data in enumerate(frames))
    return Batch(
        observations,
        want.cases,
        all(r.matches_expected for r in observations),
        set(want.cases) == set(CASES),
    )

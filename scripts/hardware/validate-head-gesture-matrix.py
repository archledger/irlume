#!/usr/bin/env python3
"""Validate privacy-bounded JSONL evidence for the head-gesture matrix."""

import datetime
import json
import math
import pathlib
import re
import stat
import sys

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_RECORDS = 512
HOSTS = {"current", "archhost", "minihost", "thinkpad"}
GESTURES = {"nod", "shake", "still", "look-around", "look-down-and-hold"}
SERVICES = {
    "capability",
    "gesturecap",
    "sudo",
    "su",
    "doas",
    "sudo-i",
    "su-l",
    "runuser",
    "polkit-1",
    "kde",
    "gdm-password",
    "sddm",
    "plasmalogin",
    "credential_release",
}
PURPOSES = {"capability", "detector", "authentication", "policy", "credential-release"}
POLICIES = {"required", "off", "not-applicable"}
OUTCOMES = {
    "capability-present",
    "capability-not-present",
    "approved",
    "declined",
    "no-gesture",
    "policy-required",
    "policy-off",
    "fallback-preserved",
    "prompt-once",
    "prompt-zero",
}
RECORD_KEYS = {
    "schema_version",
    "record_type",
    "frozen_commit_oid",
    "release_binary_sha256",
    "host_label",
    "camera_identity_digest",
    "service",
    "purpose",
    "requested_policy",
    "resolved_policy",
    "trial_id",
    "expected_gesture",
    "typed_outcome",
    "detector_evidence",
    "timestamp",
}
EVIDENCE_KEYS = {
    "frames",
    "face_frames",
    "pitch_range",
    "yaw_range",
    "pitch_crossings",
    "yaw_crossings",
    "mean_step",
}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TRIAL_ID = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,95}\Z")
FORBIDDEN_KEYS = ("serial", "username", "embedding", "template", "image", "raw_frame", "frame_path")


def fail(message):
    raise SystemExit(f"head-gesture-matrix: {message}")


def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON member: {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    fail(f"non-standard JSON number: {value}")


def finite(value, label, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        fail(f"{label}: expected a finite number")
    if not low <= value <= high:
        fail(f"{label}: outside [{low}, {high}]")
    return value


def integer(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        fail(f"{label}: expected an integer in [{low}, {high}]")
    return value


def scan_privacy(value):
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = key.lower().replace("-", "_")
            if any(token in lowered for token in FORBIDDEN_KEYS):
                fail(f"privacy-sensitive key is forbidden: {key!r}")
            scan_privacy(child)
    elif isinstance(value, list):
        for child in value:
            scan_privacy(child)
    elif isinstance(value, str):
        lowered = value.lower()
        if "/dev/video" in lowered or lowered.startswith("/dev/"):
            fail("camera device paths are forbidden")


def validate_timestamp(value, label):
    if not isinstance(value, str) or len(value) != 20:
        fail(f"{label}: expected UTC RFC3339 seconds")
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"{label}: expected UTC RFC3339 seconds")


def validate_evidence(value, label, capability):
    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        fail(f"{label}: unexpected detector evidence keys")
    frames = integer(value["frames"], f"{label}.frames", 0 if capability else 1, 300)
    face_frames = integer(value["face_frames"], f"{label}.face_frames", 0, frames)
    finite(value["pitch_range"], f"{label}.pitch_range", 0, 4)
    finite(value["yaw_range"], f"{label}.yaw_range", 0, 360)
    integer(value["pitch_crossings"], f"{label}.pitch_crossings", 0, frames)
    integer(value["yaw_crossings"], f"{label}.yaw_crossings", 0, frames)
    finite(value["mean_step"], f"{label}.mean_step", 0, 10)
    if capability and (frames != 0 or face_frames != 0 or any(value[key] != 0 for key in EVIDENCE_KEYS - {"frames", "face_frames"})):
        fail(f"{label}: capability records carry zero detector evidence")


def validate_record(record, index):
    label = f"record {index}"
    if not isinstance(record, dict):
        fail(f"{label}: expected an object")
    scan_privacy(record)
    if set(record) != RECORD_KEYS:
        fail(f"{label}: unexpected record keys: {sorted(record)}")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        fail(f"{label}: unsupported schema version")
    if record["record_type"] not in {"capability", "trial"}:
        fail(f"{label}: unknown record type")
    if not isinstance(record["frozen_commit_oid"], str) or not HEX40.fullmatch(record["frozen_commit_oid"]):
        fail(f"{label}: invalid frozen commit OID")
    if not isinstance(record["release_binary_sha256"], str) or not HEX64.fullmatch(record["release_binary_sha256"]):
        fail(f"{label}: invalid release binary digest")
    if record["host_label"] not in HOSTS:
        fail(f"{label}: unknown host label")
    digest = record["camera_identity_digest"]
    if digest is not None and (not isinstance(digest, str) or not HEX64.fullmatch(digest)):
        fail(f"{label}: invalid camera identity digest")
    if record["service"] not in SERVICES:
        fail(f"{label}: unknown service")
    if record["purpose"] not in PURPOSES:
        fail(f"{label}: unknown purpose")
    if record["requested_policy"] not in POLICIES or record["resolved_policy"] not in POLICIES:
        fail(f"{label}: unknown policy")
    if record["typed_outcome"] not in OUTCOMES:
        fail(f"{label}: unknown typed outcome")
    validate_timestamp(record["timestamp"], f"{label}.timestamp")

    capability = record["record_type"] == "capability"
    validate_evidence(record["detector_evidence"], f"{label}.detector_evidence", capability)
    if capability:
        if (
            record["service"] != "capability"
            or record["purpose"] != "capability"
            or record["requested_policy"] != "not-applicable"
            or record["resolved_policy"] != "not-applicable"
            or record["trial_id"] is not None
            or record["expected_gesture"] != "none"
            or record["typed_outcome"] not in {"capability-present", "capability-not-present"}
        ):
            fail(f"{label}: malformed capability record")
        if (record["typed_outcome"] == "capability-present") != (digest is not None):
            fail(f"{label}: capability outcome and camera digest disagree")
        return

    if digest is None:
        fail(f"{label}: a trial requires a camera digest")
    if not isinstance(record["trial_id"], str) or not TRIAL_ID.fullmatch(record["trial_id"]):
        fail(f"{label}: invalid trial ID")
    if record["expected_gesture"] not in GESTURES:
        fail(f"{label}: unknown expected gesture")
    if record["service"] == "capability" or record["purpose"] == "capability":
        fail(f"{label}: capability is not a trial service or purpose")
    if record["purpose"] == "detector":
        expected_outcome = {"nod": "approved", "shake": "declined"}.get(record["expected_gesture"], "no-gesture")
        if (
            record["service"] != "gesturecap"
            or record["requested_policy"] != "not-applicable"
            or record["resolved_policy"] != "not-applicable"
            or record["typed_outcome"] != expected_outcome
        ):
            fail(f"{label}: detector trial outcome or policy disagrees with its cell")
    elif record["service"] == "gesturecap":
        fail(f"{label}: gesturecap is only valid for detector trials")


def load_records(path):
    try:
        info = path.lstat()
    except OSError as error:
        fail(f"cannot stat evidence: {error}")
    if not stat.S_ISREG(info.st_mode):
        fail("evidence must be a regular file, not a symlink or device")
    if info.st_size > MAX_FILE_BYTES:
        fail(f"evidence exceeds {MAX_FILE_BYTES} bytes")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"cannot read UTF-8 evidence: {error}")
    records = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if len(line.encode()) > MAX_LINE_BYTES:
            fail(f"line {line_number} exceeds {MAX_LINE_BYTES} bytes")
        if not line.strip():
            fail(f"line {line_number}: blank lines are forbidden")
        try:
            record = json.loads(
                line,
                object_pairs_hook=object_without_duplicates,
                parse_constant=reject_constant,
            )
        except json.JSONDecodeError as error:
            fail(f"line {line_number}: malformed JSON: {error}")
        records.append(record)
        if len(records) > MAX_RECORDS:
            fail(f"evidence exceeds {MAX_RECORDS} records")
    if not records:
        fail("evidence contains no records")
    return records


def validate_matrix(records):
    for index, record in enumerate(records, 1):
        validate_record(record, index)

    oids = {record["frozen_commit_oid"] for record in records}
    binaries = {record["release_binary_sha256"] for record in records}
    if len(oids) != 1:
        fail("mixed frozen commit OIDs")
    if len(binaries) != 1:
        fail("mixed release binary digests")

    capabilities = {}
    trials = []
    trial_ids = set()
    for record in records:
        host = record["host_label"]
        if record["record_type"] == "capability":
            if host in capabilities:
                fail(f"duplicate capability record for {host}")
            capabilities[host] = record
            continue
        if record["trial_id"] in trial_ids:
            fail(f"duplicate trial ID: {record['trial_id']}")
        trial_ids.add(record["trial_id"])
        trials.append(record)

    if set(capabilities) != HOSTS:
        fail(f"missing host capability records: {sorted(HOSTS - set(capabilities))}")
    for host in HOSTS:
        host_trials = [record for record in trials if record["host_label"] == host]
        capability = capabilities[host]
        if capability["typed_outcome"] == "capability-not-present":
            if host_trials:
                fail(f"{host}: capability-not-present must not have trials")
            continue
        digest = capability["camera_identity_digest"]
        if any(record["camera_identity_digest"] != digest for record in host_trials):
            fail(f"{host}: mixed camera identity digests")
        for gesture in GESTURES:
            count = sum(
                record["service"] == "gesturecap"
                and record["purpose"] == "detector"
                and record["expected_gesture"] == gesture
                for record in host_trials
            )
            if count < 5:
                fail(f"{host}/{gesture}: expected at least five detector attempts, got {count}")

    absent = sum(record["typed_outcome"] == "capability-not-present" for record in capabilities.values())
    return next(iter(oids)), len(trials), absent


def main(argv):
    if len(argv) != 2:
        fail("usage: validate-head-gesture-matrix.py EVIDENCE.jsonl")
    oid, trials, absent = validate_matrix(load_records(pathlib.Path(argv[1])))
    print(
        "head-gesture-matrix: valid "
        f"hosts={len(HOSTS)} trials={trials} capability-not-present={absent} oid={oid}"
    )


if __name__ == "__main__":
    main(sys.argv)

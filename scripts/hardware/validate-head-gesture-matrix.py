#!/usr/bin/env python3
"""Validate privacy-bounded JSONL evidence for the head-gesture matrix."""

import datetime
import errno
import fcntl
import json
import math
import os
import pathlib
import re
import secrets
import stat
import sys
import time

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_RECORDS = 512
# Must track irlume_liveness::NOD_MIN_FACE_FRAMES: every detector cell needs a
# judged face, including negative gestures that would otherwise pass faceless.
MIN_FACE_FRAMES = 12
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
PURPOSES = {"capability", "detector", "authentication", "credential-release"}
POLICIES = {"required", "off", "not-applicable"}
OUTCOMES = {
    "capability-present",
    "capability-not-present",
    "approved",
    "declined",
    "no-gesture",
    "attempt-failed",
    "attempt-timeout",
}
FAILURE_OUTCOMES = {"attempt-failed", "attempt-timeout"}
POLICY_SERVICE_PURPOSES = {
    "sudo": "authentication",
    "su": "authentication",
    "doas": "authentication",
    "sudo-i": "authentication",
    "su-l": "authentication",
    "runuser": "authentication",
    "polkit-1": "authentication",
    "kde": "authentication",
    "gdm-password": "authentication",
    "sddm": "authentication",
    "plasmalogin": "authentication",
    "credential_release": "credential-release",
}
CELL_TABLE = {("gesturecap", "detector", "not-applicable"): GESTURES} | {
    (service, purpose, policy): {"nod", "shake"} if policy == "required" else {"none"}
    for service, purpose in POLICY_SERVICE_PURPOSES.items()
    for policy in ("required", "off")
}
RECORD_KEYS = {
    "schema_version",
    "record_type",
    "frozen_commit_oid",
    "release_binary_sha256",
    "attempt_adapter_sha256",
    "host_label",
    "camera_identity_digest",
    "service",
    "purpose",
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


class SchemaError(Exception):
    pass


def fail(message):
    raise SchemaError(f"head-gesture-matrix: {message}")


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


def validate_evidence(value, label, allow_zero):
    if not isinstance(value, dict) or set(value) != EVIDENCE_KEYS:
        fail(f"{label}: unexpected detector evidence keys")
    frames = integer(value["frames"], f"{label}.frames", 0 if allow_zero else 1, 300)
    face_frames = integer(value["face_frames"], f"{label}.face_frames", 0, frames)
    finite(value["pitch_range"], f"{label}.pitch_range", 0, 4)
    finite(value["yaw_range"], f"{label}.yaw_range", 0, 360)
    integer(value["pitch_crossings"], f"{label}.pitch_crossings", 0, frames)
    integer(value["yaw_crossings"], f"{label}.yaw_crossings", 0, frames)
    finite(value["mean_step"], f"{label}.mean_step", 0, 10)
    if frames == 0 and (face_frames != 0 or any(value[key] != 0 for key in EVIDENCE_KEYS - {"frames", "face_frames"})):
        fail(f"{label}: zero-frame records carry zero detector evidence")


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
    adapter_digest = record["attempt_adapter_sha256"]
    if adapter_digest is not None and (not isinstance(adapter_digest, str) or not HEX64.fullmatch(adapter_digest)):
        fail(f"{label}: invalid attempt-adapter digest")
    if record["host_label"] not in HOSTS:
        fail(f"{label}: unknown host label")
    digest = record["camera_identity_digest"]
    if digest is not None and (not isinstance(digest, str) or not HEX64.fullmatch(digest)):
        fail(f"{label}: invalid camera identity digest")
    if record["service"] not in SERVICES:
        fail(f"{label}: unknown service")
    if record["purpose"] not in PURPOSES:
        fail(f"{label}: unknown purpose")
    if record["resolved_policy"] not in POLICIES:
        fail(f"{label}: unknown policy")
    if record["typed_outcome"] not in OUTCOMES:
        fail(f"{label}: unknown typed outcome")
    validate_timestamp(record["timestamp"], f"{label}.timestamp")

    capability = record["record_type"] == "capability"
    validate_evidence(
        record["detector_evidence"],
        f"{label}.detector_evidence",
        capability or record["typed_outcome"] in FAILURE_OUTCOMES,
    )
    if capability:
        if (
            record["service"] != "capability"
            or record["purpose"] != "capability"
            or record["resolved_policy"] != "not-applicable"
            or record["trial_id"] is not None
            or record["expected_gesture"] != "none"
            or record["typed_outcome"] not in {"capability-present", "capability-not-present"}
        ):
            fail(f"{label}: malformed capability record")
        if (record["typed_outcome"] == "capability-present") != (digest is not None):
            fail(f"{label}: capability outcome and camera digest disagree")
        if (record["typed_outcome"] == "capability-present") != (adapter_digest is not None):
            fail(f"{label}: capability outcome and adapter digest disagree")
        return

    if digest is None:
        fail(f"{label}: a trial requires a camera digest")
    if adapter_digest is None:
        fail(f"{label}: a trial requires an adapter digest")
    if not isinstance(record["trial_id"], str) or not TRIAL_ID.fullmatch(record["trial_id"]):
        fail(f"{label}: invalid trial ID")
    if record["service"] == "capability" or record["purpose"] == "capability":
        fail(f"{label}: capability is not a trial service or purpose")
    cell = (record["service"], record["purpose"], record["resolved_policy"])
    if cell not in CELL_TABLE or record["expected_gesture"] not in CELL_TABLE[cell]:
        fail(f"{label}: service/purpose/policy/gesture combination is not allowlisted")


def wait_at_test_boundary(variable):
    if os.environ.get("IRLUME_HEAD_GESTURE_TEST_MODE") != "1":
        return
    pause_raw = os.environ.get(variable)
    if not pause_raw:
        return
    pause = pathlib.Path(pause_raw)
    ready = pause.with_suffix(".ready")
    proceed = pause.with_suffix(".continue")
    ready.write_text("ready\n", encoding="utf-8")
    deadline = time.monotonic() + 10
    while not proceed.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    if not proceed.exists():
        fail(f"timed out waiting at injected boundary: {variable}")


def open_evidence_directory(path):
    if not path.is_absolute():
        fail("evidence directory must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptors = []
    edges = []
    try:
        descriptors.append(os.open(path.anchor, flags))
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            if index == len(parts) - 1:
                wait_at_test_boundary("IRLUME_HEAD_GESTURE_TEST_PAUSE_BEFORE_DIRECTORY_OPEN")
            parent = descriptors[-1]
            descriptor = os.open(part, flags, dir_fd=parent)
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode):
                os.close(descriptor)
                fail(f"evidence path component is not a directory: {part!r}")
            edges.append((parent, part, info.st_dev, info.st_ino))
            descriptors.append(descriptor)
    except (OSError, SchemaError) as error:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        if isinstance(error, SchemaError):
            raise
        fail(f"cannot bind evidence directory ancestry: {error}")
    descriptor = descriptors[-1]
    info = os.fstat(descriptor)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        for opened in reversed(descriptors):
            os.close(opened)
        fail("evidence directory must be owned by the caller and inaccessible to group/other")
    binding = {"descriptors": descriptors, "edges": edges, "final": (info.st_dev, info.st_ino)}
    verify_binding(binding)
    return descriptor, binding


def verify_binding(binding):
    for parent, name, device, inode in binding["edges"]:
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            fail(f"bound evidence directory ancestry changed: {error}")
        if stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
            fail("bound evidence directory ancestry changed during operation")
    final = os.fstat(binding["descriptors"][-1])
    if (final.st_dev, final.st_ino) != binding["final"]:
        fail("bound final evidence directory identity changed")


def close_binding(binding):
    for descriptor in reversed(binding["descriptors"]):
        os.close(descriptor)


def open_lock(directory_fd):
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(".head-gesture.lock", flags, 0o600, dir_fd=directory_fd)
    except OSError as error:
        fail(f"cannot open evidence lock: {error}")
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        os.close(descriptor)
        fail("evidence lock has unsafe type, ownership, mode, or link count")
    return descriptor


def decode_record(raw, label):
    if len(raw) > MAX_LINE_BYTES:
        fail(f"{label} exceeds {MAX_LINE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
        record = json.loads(
            text,
            object_pairs_hook=object_without_duplicates,
            parse_constant=reject_constant,
        )
    except UnicodeError as error:
        fail(f"{label}: invalid UTF-8: {error}")
    except json.JSONDecodeError as error:
        fail(f"{label}: malformed JSON: {error}")
    return record


def load_directory_records(path):
    directory_fd, binding = open_evidence_directory(path)
    lock_fd = open_lock(directory_fd)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_SH)
        verify_binding(binding)
        names = os.listdir(directory_fd)
        unexpected = [name for name in names if name != ".head-gesture.lock" and not name.startswith(".tmp-") and not name.endswith(".json")]
        if unexpected:
            fail(f"unexpected evidence directory entries: {sorted(unexpected)}")
        records = []
        for name in sorted(name for name in names if name.endswith(".json")):
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
            except OSError as error:
                fail(f"cannot open evidence record {name!r}: {error}")
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1
                    or info.st_size > MAX_LINE_BYTES
                ):
                    fail(f"unsafe evidence record: {name!r}")
                raw = os.read(descriptor, MAX_LINE_BYTES + 1)
            finally:
                os.close(descriptor)
            records.append(decode_record(raw, name))
            if len(records) > MAX_RECORDS:
                fail(f"evidence exceeds {MAX_RECORDS} records")
        verify_binding(binding)
    finally:
        os.close(lock_fd)
        close_binding(binding)
    if not records:
        fail("evidence contains no records")
    return records


def load_records(path):
    if path.is_dir():
        return load_directory_records(path)
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


def publish_record(root, source):
    try:
        raw = source.read_bytes()
    except OSError as error:
        fail(f"cannot read record for publication: {error}")
    record = decode_record(raw, "publication record")
    return publish_record_value(root, record)


def publish_record_value(root, record):
    validate_record(record, 1)
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()

    directory_fd, binding = open_evidence_directory(root)
    lock_fd = open_lock(directory_fd)
    temporary = None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        verify_binding(binding)
        test_mode = os.environ.get("IRLUME_HEAD_GESTURE_TEST_MODE") == "1"
        forced = os.environ.get("IRLUME_HEAD_GESTURE_TEST_TOKEN") if test_mode else None
        token = forced or secrets.token_hex(16)
        target = f"{record['record_type']}-{token}.json"
        temporary = f".tmp-{secrets.token_hex(16)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if test_mode and os.environ.get("IRLUME_HEAD_GESTURE_TEST_FAIL_BEFORE_PUBLISH") == "1":
            fail("injected failure before publication")
        wait_at_test_boundary("IRLUME_HEAD_GESTURE_TEST_PAUSE_BEFORE_PUBLISH")
        verify_binding(binding)
        try:
            os.link(
                temporary,
                target,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            if error.errno == errno.EEXIST:
                fail(f"evidence target already exists: {target}")
            fail(f"cannot publish evidence record: {error}")
        os.fsync(directory_fd)
        os.unlink(temporary, dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
        verify_binding(binding)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except OSError:
                pass
        os.close(lock_fd)
        close_binding(binding)
    return root / target


def validate_schema(records):
    for index, record in enumerate(records, 1):
        validate_record(record, index)

    oids = {record["frozen_commit_oid"] for record in records}
    binaries = {record["release_binary_sha256"] for record in records}
    adapters = {record["attempt_adapter_sha256"] for record in records if record["attempt_adapter_sha256"] is not None}
    if len(oids) != 1:
        fail("mixed frozen commit OIDs")
    if len(binaries) != 1:
        fail("mixed release binary digests")
    if len(adapters) > 1:
        fail("mixed attempt-adapter digests")

    capabilities = {}
    trials = []
    trial_ids = set()
    for record in records:
        host = record["host_label"]
        if record["record_type"] == "capability":
            capabilities.setdefault(host, []).append(record)
            continue
        if record["trial_id"] in trial_ids:
            fail(f"duplicate trial ID: {record['trial_id']}")
        trial_ids.add(record["trial_id"])
        trials.append(record)

    for host, host_capabilities in capabilities.items():
        facts = {
            (
                record["typed_outcome"],
                record["camera_identity_digest"],
                record["attempt_adapter_sha256"],
            )
            for record in host_capabilities
        }
        if len(facts) != 1:
            fail(f"{host}: conflicting capability records")
    for host in HOSTS:
        camera_digests = {
            record["camera_identity_digest"]
            for record in records
            if record["host_label"] == host and record["camera_identity_digest"] is not None
        }
        if len(camera_digests) > 1:
            fail(f"{host}: mixed camera identity digests")
    return capabilities, trials, next(iter(oids))


def qualify(records):
    capabilities, trials, oid = validate_schema(records)
    reasons = []
    for host in HOSTS:
        host_trials = [record for record in trials if record["host_label"] == host]
        if host not in capabilities:
            reasons.append(f"{host}: missing capability record")
            continue
        capability = capabilities[host][0]
        if capability["typed_outcome"] == "capability-not-present":
            if host_trials:
                reasons.append(f"{host}: capability-not-present has trials")
            reasons.append(f"{host}: capability-not-present")
            continue
        digest = capability["camera_identity_digest"]
        if any(record["camera_identity_digest"] != digest for record in host_trials):
            fail(f"{host}: mixed camera identity digests")
        for gesture in GESTURES:
            cell_records = [
                record
                for record in host_trials
                if record["service"] == "gesturecap"
                and record["purpose"] == "detector"
                and record["resolved_policy"] == "not-applicable"
                and record["expected_gesture"] == gesture
            ]
            count = len(cell_records)
            if count < 5:
                reasons.append(f"{host}/{gesture}: expected at least five detector attempts, got {count}")
            expected_outcome = {"nod": "approved", "shake": "declined"}.get(gesture, "no-gesture")
            for record in cell_records:
                if record["detector_evidence"]["face_frames"] < MIN_FACE_FRAMES:
                    reasons.append(
                        f"{record['trial_id']}: too few face frames for detector qualification"
                    )
                if record["typed_outcome"] != expected_outcome:
                    reasons.append(
                        f"{record['trial_id']}: expected {expected_outcome}, observed {record['typed_outcome']}"
                    )

    return {
        "schema_valid": True,
        "qualified": not reasons,
        "records": len(records),
        "trials": len(trials),
        "frozen_commit_oid": oid,
        "reasons": reasons,
    }


def main(argv):
    if argv[1:2] == ["--check-root"]:
        if len(argv) != 3:
            fail("usage: validate-head-gesture-matrix.py --check-root EVIDENCE_ROOT")
        descriptor, binding = open_evidence_directory(pathlib.Path(argv[2]))
        lock = open_lock(descriptor)
        os.close(lock)
        close_binding(binding)
        return 0
    if argv[1:2] == ["--check-cell"]:
        if len(argv) != 6:
            fail("usage: validate-head-gesture-matrix.py --check-cell SERVICE PURPOSE POLICY GESTURE")
        cell = tuple(argv[2:5])
        if cell not in CELL_TABLE or argv[5] not in CELL_TABLE[cell]:
            fail("service/purpose/policy/gesture combination is not allowlisted")
        return 0
    if argv[1:2] == ["--publish-record"]:
        if len(argv) != 4:
            fail("usage: validate-head-gesture-matrix.py --publish-record EVIDENCE_ROOT RECORD")
        print(publish_record(pathlib.Path(argv[2]), pathlib.Path(argv[3])))
        return 0
    schema_only = argv[1:2] == ["--schema-only"]
    expected_length = 3 if schema_only else 2
    if len(argv) != expected_length:
        fail("usage: validate-head-gesture-matrix.py [--schema-only] EVIDENCE")
    records = load_records(pathlib.Path(argv[-1]))
    if schema_only:
        _, trials, oid = validate_schema(records)
        print(json.dumps({"schema_valid": True, "qualified": None, "records": len(records), "trials": len(trials), "frozen_commit_oid": oid}))
        return 0
    verdict = qualify(records)
    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["qualified"] else 3


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SchemaError as error:
        print(error, file=sys.stderr)
        sys.exit(2)

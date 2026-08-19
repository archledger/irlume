#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
    printf 'head-gesture-matrix: %s\n' "$*" >&2
    exit 2
}

usage() {
    die "usage: $0 --host-label HOST --expected-oid OID --expected-binary-sha256 SHA256 --expected-adapter-sha256 SHA256 --expected-camera-identity-digest SHA256 --evidence-root DIR --trial SERVICE:GESTURE"
}

declare -A seen=()
host_label=
expected_oid=
expected_binary_sha256=
expected_adapter_sha256=
expected_camera_digest=
evidence_root=
trial=
while (($#)); do
    case "$1" in
        --host-label|--expected-oid|--expected-binary-sha256|--expected-adapter-sha256|--expected-camera-identity-digest|--evidence-root|--trial)
            (($# >= 2)) || usage
            [[ -z ${seen[$1]:-} ]] || die "repeated argument: $1"
            seen[$1]=1
            case "$1" in
                --host-label) host_label=$2 ;;
                --expected-oid) expected_oid=$2 ;;
                --expected-binary-sha256) expected_binary_sha256=$2 ;;
                --expected-adapter-sha256) expected_adapter_sha256=$2 ;;
                --expected-camera-identity-digest) expected_camera_digest=$2 ;;
                --evidence-root) evidence_root=$2 ;;
                --trial) trial=$2 ;;
            esac
            shift 2
            ;;
        *) usage ;;
    esac
done
[[ -n $host_label && -n $expected_oid && -n $expected_binary_sha256 && -n $expected_adapter_sha256 ]] || usage
[[ -n $expected_camera_digest && -n $evidence_root && -n $trial ]] || usage

case "$host_label" in
    current|archhost|minihost|thinkpad) ;;
    *) die "unknown host label" ;;
esac
[[ $expected_oid =~ ^[0-9a-f]{40}$ ]] || die "expected OID must be 40 lowercase hexadecimal characters"
for digest in "$expected_binary_sha256" "$expected_adapter_sha256" "$expected_camera_digest"; do
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || die "expected digests must be 64 lowercase hexadecimal characters"
done
[[ $evidence_root = /* ]] || die "evidence root must be absolute"

IFS=: read -r service expected_gesture extra <<<"$trial"
[[ -z ${extra:-} && -n $service && -n $expected_gesture ]] || die "malformed trial"
case "$service" in
    gesturecap) purpose=detector ;;
    credential_release) purpose=credential-release ;;
    sudo|su|doas|sudo-i|su-l|runuser|polkit-1|kde|gdm-password|sddm|plasmalogin) purpose=authentication ;;
    *) die "unknown trial service" ;;
esac

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=${IRLUME_HEAD_GESTURE_ROOT:-"$(cd -- "$script_dir/../.." && pwd -P)"}
binary=${IRLUME_HEAD_GESTURE_BINARY:-"$root/target/release/irlume"}
adapter=${IRLUME_HEAD_GESTURE_ATTEMPT_CMD:-}
validator="$script_dir/validate-head-gesture-matrix.py"
test_mode=${IRLUME_HEAD_GESTURE_TEST_MODE:-0}
[[ $test_mode == 0 || $test_mode == 1 ]] || die "invalid test mode"
if [[ $test_mode != 1 && ( -n ${IRLUME_HEAD_GESTURE_STATUS_CMD:-} || -n ${IRLUME_HEAD_GESTURE_DOCTOR_CMD:-} ) ]]; then
    die "status/doctor overrides require explicit test mode"
fi
if [[ $test_mode != 1 && -n ${IRLUME_HEAD_GESTURE_CONTAINMENT_CMD:-} ]]; then
    die "containment override requires explicit test mode"
fi
status_cmd=$binary
doctor_cmd=$binary
if [[ $test_mode == 1 ]]; then
    status_cmd=${IRLUME_HEAD_GESTURE_STATUS_CMD:-"$binary"}
    doctor_cmd=${IRLUME_HEAD_GESTURE_DOCTOR_CMD:-"$binary"}
    containment_cmd=${IRLUME_HEAD_GESTURE_CONTAINMENT_CMD:-}
    [[ -n $containment_cmd && -f $containment_cmd && ! -L $containment_cmd && -x $containment_cmd ]] || die "test containment command must be an executable regular file"
fi
attempt_seconds=20
if [[ -n ${IRLUME_HEAD_GESTURE_TEST_TIMEOUT_SECONDS:-} ]]; then
    [[ $test_mode == 1 && ${IRLUME_HEAD_GESTURE_TEST_TIMEOUT_SECONDS} =~ ^[1-9][0-9]?$ ]] || die "test timeout override requires test mode and an integer"
    attempt_seconds=$IRLUME_HEAD_GESTURE_TEST_TIMEOUT_SECONDS
fi

[[ -d $root && ! -L $root ]] || die "repository root is not a real directory"
[[ -f $binary && ! -L $binary && -x $binary ]] || die "release binary must be an executable regular file"
[[ -n $adapter && -f $adapter && ! -L $adapter && -x $adapter ]] || die "attempt adapter must be an executable regular file, not a symlink"
[[ -f $validator && ! -L $validator ]] || die "validator is missing"
[[ -x $status_cmd && -x $doctor_cmd ]] || die "readiness commands are not executable"
validator_source=$(<"$validator") || die "cannot bind validator source"
exec {binary_fd}<"$binary" || die "cannot bind release binary"
exec {adapter_fd}<"$adapter" || die "cannot bind attempt adapter"
binary_bound="/proc/$$/fd/$binary_fd"
adapter_bound="/proc/$$/fd/$adapter_fd"
[[ -f $binary_bound && -f $adapter_bound ]] || die "bound executables are not regular files"
if [[ $test_mode != 1 ]]; then
    status_cmd=$binary_bound
    doctor_cmd=$binary_bound
fi

actual_oid=$(git -C "$root" rev-parse HEAD) || die "cannot read repository OID"
[[ $actual_oid == "$expected_oid" ]] || die "checkout OID mismatch"
[[ -z $(git -C "$root" status --porcelain --untracked-files=all) ]] || die "checkout is dirty"
sha256_file() {
    python3 - "$1" <<'PY'
import hashlib
import pathlib
import sys

digest = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}
[[ $(sha256_file "$binary_bound") == "$expected_binary_sha256" ]] || die "release binary digest mismatch"
[[ $(sha256_file "$adapter_bound") == "$expected_adapter_sha256" ]] || die "attempt adapter digest mismatch"

containment_check() {
    if [[ $test_mode == 1 ]]; then
        "$containment_cmd" check
        return
    fi
    command -v systemd-run >/dev/null || return 1
    command -v systemctl >/dev/null || return 1
    systemctl --user show-environment >/dev/null 2>&1
}

containment_cleanup() {
    local unit=$1 state control_group
    if [[ $test_mode == 1 ]]; then
        "$containment_cmd" term "$unit" || return 1
        "$containment_cmd" kill "$unit" || return 1
        "$containment_cmd" verify-empty "$unit"
        return
    fi
    systemctl --user kill --kill-whom=all --signal=TERM "$unit" >/dev/null 2>&1 || true
    systemctl --user kill --kill-whom=all --signal=KILL "$unit" >/dev/null 2>&1 || true
    systemctl --user stop "$unit" >/dev/null 2>&1 || true
    state=$(systemctl --user show --property=ActiveState --value "$unit" 2>/dev/null) || return 1
    case "$state" in
        inactive|failed) ;;
        *) return 1 ;;
    esac
    control_group=$(systemctl --user show --property=ControlGroup --value "$unit" 2>/dev/null) || return 1
    if [[ -n $control_group && -e /sys/fs/cgroup$control_group/cgroup.procs ]]; then
        [[ ! -s /sys/fs/cgroup$control_group/cgroup.procs ]] || return 1
    fi
}

containment_check || die "containment authority is unavailable"

root_real=$(cd -- "$root" && pwd -P)
evidence_real=$(cd -- "$evidence_root" && pwd -P)
case "$evidence_real/" in
    "$root_real/"*) die "live evidence root must be outside the checkout" ;;
esac
python3 "$validator" --check-root "$evidence_root" || die "unsafe evidence root"

scratch_dir=$(mktemp -d "${TMPDIR:-/tmp}/irlume-head-gesture.XXXXXX") || die "cannot create scratch directory"
scratch_files=()
active_unit=
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n $active_unit ]]; then
        containment_cleanup "$active_unit" || status=1
        active_unit=
    fi
    if ((${#scratch_files[@]})); then
        rm -f -- "${scratch_files[@]}"
    fi
    rmdir -- "$scratch_dir" 2>/dev/null || true
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

scratch_file() {
    local variable=$1 path="$scratch_dir/$2"
    : >"$path"
    scratch_files+=("$path")
    printf -v "$variable" '%s' "$path"
}

publish_cached_record() {
    python3 -I -c '
import json
import pathlib
import sys

validator_path, validator_source, source, root = sys.argv[1:]
validator = {"__name__": "irlume_matrix_validator"}
exec(compile(validator_source, validator_path, "exec"), validator)
record = json.loads(pathlib.Path(source).read_text(encoding="utf-8"))
validator["publish_record_value"](pathlib.Path(root), record)
' "$validator" "$validator_source" "$1" "$evidence_root"
}

read -r -d '' supervisor_code <<'PY' || true
import ctypes
import json
import os
import pathlib
import selectors
import subprocess
import sys
import time

MAX_STREAM_BYTES = 4096
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4


def disable_dumpability():
    if not sys.platform.startswith("linux"):
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        return False
    return prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0


def cleanup_containment(test_mode, containment, unit):
    if test_mode:
        results = []
        for operation in ("term", "kill", "verify-empty"):
            results.append(subprocess.run(
                [containment, operation, unit],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                check=False,
            ).returncode == 0)
        return all(results)
    for signal in ("TERM", "KILL"):
        subprocess.run(
            ["systemctl", "--user", "kill", "--kill-whom=all", f"--signal={signal}", unit],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            check=False,
        )
    subprocess.run(
        ["systemctl", "--user", "stop", unit],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        check=False,
    )
    state = subprocess.run(
        ["systemctl", "--user", "show", "--property=ActiveState", "--value", unit],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        check=False,
    )
    if state.returncode != 0 or state.stdout.strip() not in {b"inactive", b"failed"}:
        return False
    control_group = subprocess.run(
        ["systemctl", "--user", "show", "--property=ControlGroup", "--value", unit],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        check=False,
    )
    if control_group.returncode != 0:
        return False
    group = control_group.stdout.decode("utf-8", errors="strict").strip()
    processes = pathlib.Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.procs"
    return not processes.exists() or processes.stat().st_size == 0


def capture(command, timeout_seconds):
    try:
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            bufsize=0,
        )
    except OSError:
        return {
            "error": "spawn-failed",
            "output_overflow": False,
            "returncode": None,
            "started": False,
            "stderr": b"",
            "stdout": b"",
            "timed_out": False,
        }

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)

    def read_ready(events):
        for key, _ in events:
            name = key.data
            room = MAX_STREAM_BYTES + 1 - len(buffers[name])
            if room <= 0:
                return True
            try:
                data = os.read(key.fileobj.fileno(), room)
            except BlockingIOError:
                continue
            if not data:
                selector.unregister(key.fileobj)
                continue
            buffers[name].extend(data)
            if len(buffers[name]) > MAX_STREAM_BYTES:
                return True
        return False

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    output_overflow = False
    error = None
    try:
        while child.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(min(remaining, 0.05)) if selector.get_map() else ()
            if not selector.get_map():
                time.sleep(min(remaining, 0.05))
            if read_ready(events):
                output_overflow = True
                break
        if not timed_out and not output_overflow:
            while selector.get_map():
                events = selector.select(0)
                if not events:
                    break
                if read_ready(events):
                    output_overflow = True
                    break
    except (OSError, ValueError):
        error = "internal-error"
    finally:
        if child.poll() is None:
            child.kill()
        raw_returncode = child.wait()
        selector.close()
        child.stdout.close()
        child.stderr.close()

    return {
        "error": error,
        "output_overflow": output_overflow,
        "returncode": raw_returncode if raw_returncode >= 0 else 128 - raw_returncode,
        "started": True,
        "stderr": bytes(buffers["stderr"][:MAX_STREAM_BYTES]),
        "stdout": bytes(buffers["stdout"][:MAX_STREAM_BYTES]),
        "timed_out": timed_out,
    }


try:
    protected = disable_dumpability()
except (AttributeError, OSError):
    protected = False
if not protected:
    raise SystemExit(70)

(
    phase, timeout_raw, test_mode_raw, containment, unit, adapter,
    validator_path, camera, validator_source,
) = sys.argv[1:10]
timeout_seconds = int(timeout_raw)
test_mode = test_mode_raw == "1"
validator = {"__name__": "irlume_matrix_validator"}
try:
    exec(compile(validator_source, validator_path, "exec"), validator)
except (OSError, RuntimeError, SyntaxError, ValueError):
    raise SystemExit(70)

if phase == "preflight":
    adapter_arguments = [
        "--preflight",
        "--expected-camera-identity-digest", camera,
        "--candidate-binary", sys.argv[10],
    ]
elif phase == "attempt":
    adapter_arguments = [
        "--service", sys.argv[16],
        "--purpose", sys.argv[17],
        "--expected-gesture", sys.argv[20],
        "--expected-camera-identity-digest", camera,
        "--timeout-seconds", "20",
        "--candidate-binary", sys.argv[10],
    ]
else:
    raise SystemExit(70)

contained = (
    [containment, "run", unit, adapter, *adapter_arguments]
    if test_mode
    else ["systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}", "--", adapter, *adapter_arguments]
)
captured = capture(contained, timeout_seconds)
cleanup_ok = cleanup_containment(test_mode, containment, unit) if captured["started"] else True

if phase == "preflight":
    try:
        document = json.loads(captured["stdout"].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise SystemExit(70)
    if (
        not cleanup_ok
        or captured["error"] is not None
        or captured["timed_out"]
        or captured["output_overflow"]
        or captured["returncode"] != 0
        or not isinstance(document, dict)
        or set(document) != {"camera_identity_digest"}
        or document["camera_identity_digest"] != camera
    ):
        raise SystemExit(70)
    raise SystemExit(0)

(
    evidence_root, oid, binary_digest, adapter_digest, host, service, purpose,
    policy, trial_id, gesture, timestamp,
) = sys.argv[11:22]
zero = {
    "frames": 0,
    "face_frames": 0,
    "pitch_range": 0,
    "yaw_range": 0,
    "pitch_crossings": 0,
    "yaw_crossings": 0,
    "mean_step": 0,
}
result = None
try:
    candidate = json.loads(captured["stdout"].decode("utf-8"))
    adapter_outcomes = validator["OUTCOMES"] - {
        "attempt-timeout", "capability-present", "capability-not-present",
    }
    if (
        isinstance(candidate, dict)
        and set(candidate) == {"typed_outcome", "detector_evidence"}
        and isinstance(candidate["typed_outcome"], str)
        and candidate["typed_outcome"] in adapter_outcomes
    ):
        validator["validate_evidence"](
            candidate["detector_evidence"],
            "adapter.detector_evidence",
            candidate["typed_outcome"] in validator["FAILURE_OUTCOMES"],
        )
        result = candidate
except (UnicodeError, ValueError, json.JSONDecodeError, validator["SchemaError"]):
    pass

evidence = result["detector_evidence"] if result is not None else zero
if cleanup_ok and captured["started"] and captured["error"] is None and captured["timed_out"]:
    result = {"typed_outcome": "attempt-timeout", "detector_evidence": evidence}
elif (
    not cleanup_ok
    or not captured["started"]
    or captured["error"] is not None
    or captured["output_overflow"]
    or captured["returncode"] != 0
    or result is None
):
    result = {"typed_outcome": "attempt-failed", "detector_evidence": evidence}

record = {
    "schema_version": 1,
    "record_type": "trial",
    "frozen_commit_oid": oid,
    "release_binary_sha256": binary_digest,
    "attempt_adapter_sha256": adapter_digest,
    "host_label": host,
    "camera_identity_digest": camera,
    "service": service,
    "purpose": purpose,
    "resolved_policy": policy,
    "trial_id": trial_id,
    "expected_gesture": gesture,
    "typed_outcome": result["typed_outcome"],
    "detector_evidence": result["detector_evidence"],
    "timestamp": timestamp,
}
try:
    validator["publish_record_value"](pathlib.Path(evidence_root), record)
except (OSError, validator["SchemaError"]):
    raise SystemExit(70)
raise SystemExit(4 if result["typed_outcome"] in validator["FAILURE_OUTCOMES"] else 0)
PY

status_json=
scratch_file status_json status.json
"$status_cmd" status --json --contract 1 >"$status_json" || die "status API failed"
camera_state=$(python3 - "$status_json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 4096:
    raise SystemExit("oversized status document")
doc = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(doc, dict) or doc.get("ok") is not True or not isinstance(doc.get("data"), dict):
    raise SystemExit("invalid status envelope")
data = doc["data"]
if data.get("daemon") != "running":
    raise SystemExit("daemon is not ready")
camera = data.get("camera")
if not isinstance(camera, dict) or type(camera.get("rgb")) is not bool or type(camera.get("ir")) is not bool:
    raise SystemExit("invalid camera capability")
print("present" if camera["rgb"] and camera["ir"] else "absent")
PY
) || die "daemon/camera status is not ready"

make_capability_record() {
    local outcome=$1 adapter_digest=$2 camera_digest=$3 destination=$4 timestamp=$5
    python3 - "$outcome" "$adapter_digest" "$camera_digest" "$destination" "$timestamp" \
        "$expected_oid" "$expected_binary_sha256" "$host_label" <<'PY'
import json
import pathlib
import sys

outcome, adapter, camera, destination, timestamp, oid, binary, host = sys.argv[1:]
record = {
    "schema_version": 1,
    "record_type": "capability",
    "frozen_commit_oid": oid,
    "release_binary_sha256": binary,
    "attempt_adapter_sha256": adapter or None,
    "host_label": host,
    "camera_identity_digest": camera or None,
    "service": "capability",
    "purpose": "capability",
    "resolved_policy": "not-applicable",
    "trial_id": None,
    "expected_gesture": "none",
    "typed_outcome": outcome,
    "detector_evidence": {"frames": 0, "face_frames": 0, "pitch_range": 0, "yaw_range": 0, "pitch_crossings": 0, "yaw_crossings": 0, "mean_step": 0},
    "timestamp": timestamp,
}
pathlib.Path(destination).write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
}

if [[ $camera_state == absent ]]; then
    capability_record=
    scratch_file capability_record capability.json
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    make_capability_record capability-not-present "" "" "$capability_record" "$timestamp"
    publish_cached_record "$capability_record" || die "cannot publish capability record"
    printf '{"schema_valid":true,"qualified":false,"reason":"capability-not-present","host_label":"%s"}\n' "$host_label"
    exit 3
fi

doctor_json=
scratch_file doctor_json doctor.json
"$doctor_cmd" doctor --json --contract 1 >"$doctor_json" || die "doctor API failed"
python3 - "$doctor_json" <<'PY' || die "doctor reports the camera stack is not ready"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 65536:
    raise SystemExit("oversized doctor document")
doc = json.loads(path.read_text(encoding="utf-8"))
checks = doc.get("data", {}).get("checks") if isinstance(doc, dict) and doc.get("ok") is True else None
if not isinstance(checks, list):
    raise SystemExit("invalid doctor envelope")
states = {check.get("id"): check.get("state") for check in checks if isinstance(check, dict)}
required = {"camera-nodes", "models", "stage-detection-model", "stage-recognition-model"}
if any(states.get(check) != "pass" for check in required):
    raise SystemExit("required doctor check did not pass")
PY

resolved_policy=not-applicable
if [[ $service != gesturecap ]]; then
    policy_text=$($binary_bound credential-release-challenge "$service" status) || die "candidate could not report effective service policy"
    case "$policy_text" in
        *": REQUIRED "*) resolved_policy=required ;;
        *": off "*) resolved_policy=off ;;
        *) die "candidate policy observation was not authoritative" ;;
    esac
fi
python3 "$validator" --check-cell "$service" "$purpose" "$resolved_policy" "$expected_gesture" || die "trial cell is not allowlisted"

run_adapter() {
    local phase=$1 seconds=$2
    shift 2
    local unit="irlume-head-gesture-$phase-$$-$RANDOM.scope"
    local outer_seconds=$((seconds + 3)) status containment_ok=1
    active_unit=$unit
    set +e
    timeout --foreground --kill-after=2s "${outer_seconds}s" \
        python3 -I -c "$supervisor_code" "$phase" "$seconds" "$test_mode" \
        "${containment_cmd:--}" "$unit" "$adapter_bound" "$validator" \
        "$expected_camera_digest" "$validator_source" "$binary_bound" "$@"
    status=$?
    set -e
    case "$status" in
        0|4) ;;
        *) containment_cleanup "$unit" || containment_ok=0 ;;
    esac
    active_unit=
    RUN_SUPERVISOR_STATUS=$status
    RUN_CONTAINMENT_OK=$containment_ok
}

run_adapter preflight 5
[[ $RUN_SUPERVISOR_STATUS == 0 && $RUN_CONTAINMENT_OK == 1 ]] || die "adapter preflight result was invalid"

printf 'head-gesture-matrix: service=%s purpose=%s expected-pose=%s resolved-policy=%s\n' \
    "$service" "$purpose" "$expected_gesture" "$resolved_policy"
printf 'Type literal ready to begin this bounded attempt: '
IFS= read -r confirmation || die "readiness confirmation ended"
[[ $confirmation == ready ]] || die "literal ready was not received; no attempt started"

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
trial_id="$host_label:$service:$expected_gesture:$(date -u +%Y%m%d%H%M%S):$$"
run_adapter attempt "$attempt_seconds" \
    "$evidence_root" "$expected_oid" "$expected_binary_sha256" "$expected_adapter_sha256" \
    "$host_label" "$service" "$purpose" "$resolved_policy" "$trial_id" "$expected_gesture" "$timestamp"
attempt_status=$RUN_SUPERVISOR_STATUS

if [[ $attempt_status != 0 && $attempt_status != 4 ]]; then
    [[ $RUN_CONTAINMENT_OK == 1 ]] || die "attempt coordinator failed and containment cleanup was not verified"
    trial_record=
    scratch_file trial_record trial.json
    python3 - "$trial_record" "$expected_oid" "$expected_binary_sha256" "$expected_adapter_sha256" \
        "$expected_camera_digest" "$host_label" "$service" "$purpose" "$resolved_policy" \
        "$trial_id" "$expected_gesture" "$timestamp" <<'PY'
import json
import pathlib
import sys

destination, oid, binary, adapter, camera, host, service, purpose, policy, trial_id, gesture, timestamp = sys.argv[1:]
record = {
    "schema_version": 1,
    "record_type": "trial",
    "frozen_commit_oid": oid,
    "release_binary_sha256": binary,
    "attempt_adapter_sha256": adapter,
    "host_label": host,
    "camera_identity_digest": camera,
    "service": service,
    "purpose": purpose,
    "resolved_policy": policy,
    "trial_id": trial_id,
    "expected_gesture": gesture,
    "typed_outcome": "attempt-failed",
    "detector_evidence": {"frames": 0, "face_frames": 0, "pitch_range": 0, "yaw_range": 0, "pitch_crossings": 0, "yaw_crossings": 0, "mean_step": 0},
    "timestamp": timestamp,
}
pathlib.Path(destination).write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
    publish_cached_record "$trial_record" || die "cannot publish failed attempt record"
    attempt_status=4
fi

capability_record=
scratch_file capability_record capability.json
make_capability_record capability-present "$expected_adapter_sha256" "$expected_camera_digest" "$capability_record" "$timestamp"
publish_cached_record "$capability_record" || die "cannot publish capability record"
printf 'head-gesture-matrix: recorded host=%s trial=%s\n' "$host_label" "$trial_id"
exit "$attempt_status"

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

supervisor=
scratch_file supervisor supervise.py
chmod 0700 "$supervisor"
python3 - "$supervisor" <<'PY'
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(
    """#!/usr/bin/env python3
import os
import stat
import subprocess
import sys

marker, *command = sys.argv[1:]
try:
    child = subprocess.Popen(command)
    returncode = child.wait()
    status = returncode if returncode >= 0 else 128 - returncode
except OSError:
    status = 127

flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
descriptor = os.open(marker, flags, 0o600)
try:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise SystemExit(125)
    payload = f"{status}\\n".encode("ascii")
    view = memoryview(payload)
    while view:
        view = view[os.write(descriptor, view):]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
raise SystemExit(status)
""",
    encoding="utf-8",
)
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
print("present" if camera["rgb"] else "absent")
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
    python3 "$validator" --publish-record "$evidence_root" "$capability_record" || die "cannot publish capability record"
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
    local stdout_file="$scratch_dir/$phase.stdout" stderr_file="$scratch_dir/$phase.stderr"
    local stdout_fifo="$scratch_dir/$phase.stdout.fifo" stderr_fifo="$scratch_dir/$phase.stderr.fifo"
    local completion_file="$scratch_dir/$phase.completion"
    : >"$stdout_file"
    : >"$stderr_file"
    mkfifo "$stdout_fifo" "$stderr_fifo"
    scratch_files+=("$stdout_file" "$stderr_file" "$stdout_fifo" "$stderr_fifo" "$completion_file")
    if [[ $test_mode == 1 && $phase == attempt && -n ${IRLUME_HEAD_GESTURE_TEST_COMPLETION_SYMLINK:-} ]]; then
        ln -s -- "$IRLUME_HEAD_GESTURE_TEST_COMPLETION_SYMLINK" "$completion_file"
    fi
    head -c 4097 <"$stdout_fifo" >"$stdout_file" &
    local stdout_reader=$!
    head -c 4097 <"$stderr_fifo" >"$stderr_file" &
    local stderr_reader=$!
    local unit="irlume-head-gesture-$phase-$$-$RANDOM.scope"
    active_unit=$unit
    set +e
    if [[ $test_mode == 1 ]]; then
        timeout --foreground --kill-after=2s "${seconds}s" \
            "$containment_cmd" run "$unit" python3 "$supervisor" "$completion_file" "$adapter_bound" "$@" >"$stdout_fifo" 2>"$stderr_fifo"
    else
        timeout --foreground --kill-after=2s "${seconds}s" \
            systemd-run --user --scope --quiet --unit="$unit" -- \
            python3 "$supervisor" "$completion_file" "$adapter_bound" "$@" >"$stdout_fifo" 2>"$stderr_fifo"
    fi
    local status=$?
    set -e
    local containment_ok=1
    containment_cleanup "$unit" || containment_ok=0
    active_unit=
    wait "$stdout_reader" 2>/dev/null || true
    wait "$stderr_reader" 2>/dev/null || true
    RUN_STDOUT=$stdout_file
    RUN_STDERR=$stderr_file
    RUN_CONTAINMENT_OK=$containment_ok
    RUN_ADAPTER_COMPLETED=0
    RUN_ADAPTER_STATUS=
    if [[ -e $completion_file || -L $completion_file ]]; then
        local completion_status
        if completion_status=$(python3 - "$completion_file" <<'PY'
import os
import stat
import sys

flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
descriptor = os.open(sys.argv[1], flags)
try:
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
        or not 2 <= info.st_size <= 4
    ):
        raise SystemExit(1)
    raw = os.read(descriptor, 5)
finally:
    os.close(descriptor)
try:
    text = raw.decode("ascii")
    if not text.endswith("\n") or not text[:-1].isdigit():
        raise ValueError
    status = int(text[:-1])
except (UnicodeError, ValueError):
    raise SystemExit(1)
if not 0 <= status <= 255:
    raise SystemExit(1)
print(status)
PY
        ); then
            RUN_ADAPTER_COMPLETED=1
            RUN_ADAPTER_STATUS=$completion_status
        fi
    fi
    RUN_WATCHDOG_EXPIRED=0
    if [[ $RUN_ADAPTER_COMPLETED -eq 0 && ( $status -eq 124 || $status -eq 137 ) ]]; then
        RUN_WATCHDOG_EXPIRED=1
    fi
}

run_adapter preflight 5 --preflight --expected-camera-identity-digest "$expected_camera_digest"
[[ $RUN_CONTAINMENT_OK -eq 1 && $RUN_ADAPTER_COMPLETED -eq 1 && $RUN_ADAPTER_STATUS -eq 0 ]] || die "adapter preflight failed"
preflight_digest=$(python3 - "$RUN_STDOUT" "$RUN_STDERR" <<'PY'
import json
import pathlib
import sys

stdout, stderr = map(pathlib.Path, sys.argv[1:])
if stdout.stat().st_size > 4096 or stderr.stat().st_size > 4096:
    raise SystemExit("oversized preflight output")
doc = json.loads(stdout.read_text(encoding="utf-8"))
if not isinstance(doc, dict) or set(doc) != {"camera_identity_digest"}:
    raise SystemExit("invalid preflight result")
print(doc["camera_identity_digest"])
PY
) || die "adapter preflight result was invalid"
[[ $preflight_digest == "$expected_camera_digest" ]] || die "adapter preflight camera digest mismatch"

printf 'head-gesture-matrix: service=%s purpose=%s expected-pose=%s resolved-policy=%s\n' \
    "$service" "$purpose" "$expected_gesture" "$resolved_policy"
printf 'Type literal ready to begin this bounded attempt: '
IFS= read -r confirmation || die "readiness confirmation ended"
[[ $confirmation == ready ]] || die "literal ready was not received; no attempt started"

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_adapter attempt "$attempt_seconds" \
    --service "$service" \
    --purpose "$purpose" \
    --expected-gesture "$expected_gesture" \
    --expected-camera-identity-digest "$expected_camera_digest" \
    --timeout-seconds 20

trial_record=
scratch_file trial_record trial.json
trial_id="$host_label:$service:$expected_gesture:$(date -u +%Y%m%d%H%M%S):$$"
normalization=$(python3 - "$RUN_STDOUT" "$RUN_STDERR" "$RUN_WATCHDOG_EXPIRED" "$RUN_ADAPTER_COMPLETED" "$RUN_ADAPTER_STATUS" "$RUN_CONTAINMENT_OK" "$trial_record" \
    "$expected_oid" "$expected_binary_sha256" "$expected_adapter_sha256" "$expected_camera_digest" \
    "$host_label" "$service" "$purpose" "$resolved_policy" "$trial_id" "$expected_gesture" "$timestamp" "$validator" <<'PY'
import json
import pathlib
import runpy
import sys

(
    stdout_raw, stderr_raw, watchdog_raw, completed_raw, adapter_status_raw, containment_raw, destination_raw, oid, binary, adapter,
    camera, host, service, purpose, policy, trial_id, gesture, timestamp, validator_raw,
) = sys.argv[1:]
stdout = pathlib.Path(stdout_raw)
stderr = pathlib.Path(stderr_raw)
watchdog_expired = watchdog_raw == "1"
completed = completed_raw == "1"
adapter_status = int(adapter_status_raw) if completed else None
containment_ok = containment_raw == "1"
zero = {"frames": 0, "face_frames": 0, "pitch_range": 0, "yaw_range": 0, "pitch_crossings": 0, "yaw_crossings": 0, "mean_step": 0}
result = None
validator = runpy.run_path(validator_raw)
if stdout.stat().st_size <= 4096 and stderr.stat().st_size <= 4096:
    try:
        candidate = json.loads(stdout.read_text(encoding="utf-8"))
        if (
            isinstance(candidate, dict)
            and set(candidate) == {"typed_outcome", "detector_evidence"}
            and candidate["typed_outcome"] in validator["OUTCOMES"] - {"capability-present", "capability-not-present"}
        ):
            try:
                validator["validate_evidence"](
                    candidate["detector_evidence"],
                    "adapter.detector_evidence",
                    candidate["typed_outcome"] in validator["FAILURE_OUTCOMES"],
                )
            except validator["SchemaError"]:
                pass
            else:
                result = candidate
    except (UnicodeError, json.JSONDecodeError):
        pass
evidence = result["detector_evidence"] if result is not None else zero
if watchdog_expired:
    result = {"typed_outcome": "attempt-timeout", "detector_evidence": evidence}
elif not containment_ok or not completed or adapter_status != 0 or result is None:
    result = {"typed_outcome": "attempt-failed", "detector_evidence": evidence}
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
    "typed_outcome": result["typed_outcome"],
    "detector_evidence": result["detector_evidence"],
    "timestamp": timestamp,
}
pathlib.Path(destination_raw).write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
print(record["typed_outcome"])
PY
) || die "cannot normalize bounded attempt result"

python3 "$validator" --publish-record "$evidence_root" "$trial_record" || die "cannot publish trial record"
capability_record=
scratch_file capability_record capability.json
make_capability_record capability-present "$expected_adapter_sha256" "$expected_camera_digest" "$capability_record" "$timestamp"
python3 "$validator" --publish-record "$evidence_root" "$capability_record" || die "cannot publish capability record"
printf 'head-gesture-matrix: recorded host=%s trial=%s outcome=%s\n' "$host_label" "$trial_id" "$normalization"
case "$normalization" in
    attempt-failed|attempt-timeout) exit 4 ;;
    *) exit 0 ;;
esac

#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
    printf 'head-gesture-matrix: %s\n' "$*" >&2
    exit 2
}

usage() {
    die "usage: $0 --host-label HOST --expected-oid OID --expected-binary-sha256 SHA256 --output FILE --trial SERVICE:GESTURE:POLICY"
}

host_label=
expected_oid=
expected_binary_sha256=
output=
trial=
while (($#)); do
    case "$1" in
        --host-label|--expected-oid|--expected-binary-sha256|--output|--trial)
            (($# >= 2)) || usage
            case "$1" in
                --host-label) host_label=$2 ;;
                --expected-oid) expected_oid=$2 ;;
                --expected-binary-sha256) expected_binary_sha256=$2 ;;
                --output) output=$2 ;;
                --trial) trial=$2 ;;
            esac
            shift 2
            ;;
        *) usage ;;
    esac
done
[[ -n $host_label && -n $expected_oid && -n $expected_binary_sha256 && -n $output && -n $trial ]] || usage

case "$host_label" in
    current|archhost|minihost|thinkpad) ;;
    *) die "unknown host label" ;;
esac
[[ $expected_oid =~ ^[0-9a-f]{40}$ ]] || die "expected OID must be 40 lowercase hexadecimal characters"
[[ $expected_binary_sha256 =~ ^[0-9a-f]{64}$ ]] || die "expected binary digest must be 64 lowercase hexadecimal characters"
[[ $output = /* ]] || die "output path must be absolute"

IFS=: read -r service expected_gesture requested_policy extra <<<"$trial"
[[ -z ${extra:-} && -n $service && -n $expected_gesture && -n $requested_policy ]] || die "malformed trial"
case "$expected_gesture" in
    nod|shake|still|look-around|look-down-and-hold) ;;
    *) die "unknown trial gesture" ;;
esac
case "$service" in
    gesturecap)
        [[ $requested_policy == not-applicable ]] || die "gesturecap policy must be not-applicable"
        purpose=detector
        ;;
    credential_release)
        [[ $requested_policy == required || $requested_policy == off ]] || die "unknown requested policy"
        purpose=credential-release
        ;;
    sudo|su|doas|sudo-i|su-l|runuser|polkit-1|kde|gdm-password|sddm|plasmalogin)
        [[ $requested_policy == required || $requested_policy == off ]] || die "unknown requested policy"
        purpose=authentication
        ;;
    *) die "unknown trial service" ;;
esac

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=${IRLUME_HEAD_GESTURE_ROOT:-"$(cd -- "$script_dir/../.." && pwd -P)"}
binary=${IRLUME_HEAD_GESTURE_BINARY:-"$root/target/release/irlume"}
validator="$script_dir/validate-head-gesture-matrix.py"
status_cmd=${IRLUME_HEAD_GESTURE_STATUS_CMD:-"$binary"}
doctor_cmd=${IRLUME_HEAD_GESTURE_DOCTOR_CMD:-"$binary"}
attempt_cmd=${IRLUME_HEAD_GESTURE_ATTEMPT_CMD:-}
policy_cmd=${IRLUME_HEAD_GESTURE_POLICY_CMD:-"$binary"}

[[ -d $root && ! -L $root ]] || die "repository root is not a real directory"
[[ -f $binary && ! -L $binary && -x $binary ]] || die "release binary must be an executable regular file"
[[ -f $validator && ! -L $validator ]] || die "validator is missing"
[[ -x $status_cmd && -x $doctor_cmd ]] || die "readiness commands are not executable"
[[ -n $attempt_cmd && -x $attempt_cmd ]] || die "IRLUME_HEAD_GESTURE_ATTEMPT_CMD must name a reviewed executable"
if [[ $service != gesturecap ]]; then
    [[ -x $policy_cmd ]] || die "policy command is not executable"
fi

actual_oid=$(git -C "$root" rev-parse HEAD) || die "cannot read repository OID"
[[ $actual_oid == "$expected_oid" ]] || die "checkout OID mismatch"
[[ -z $(git -C "$root" status --porcelain --untracked-files=all) ]] || die "checkout is dirty"
actual_binary_sha256=$(python3 - "$binary" <<'PY'
import hashlib
import pathlib
import sys

digest = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
) || die "cannot hash release binary"
[[ $actual_binary_sha256 == "$expected_binary_sha256" ]] || die "release binary digest mismatch"

output_dir=$(dirname -- "$output")
[[ -d $output_dir && ! -L $output_dir ]] || die "output directory must be an existing real directory"
if [[ -e $output || -L $output ]]; then
    [[ -f $output && ! -L $output ]] || die "existing output must be a regular file"
fi

scratch=()
output_tmp=
policy_changed=0
original_policy=
cleanup() {
    local status=$?
    trap - EXIT
    if ((policy_changed)); then
        if ! "$policy_cmd" credential-release-challenge "$service" "$original_policy" --yes >/dev/null; then
            printf 'head-gesture-matrix: failed to restore %s policy to %s\n' "$service" "$original_policy" >&2
            status=1
        fi
    fi
    if [[ -n $output_tmp && -e $output_tmp ]]; then
        rm -f -- "$output_tmp"
    fi
    if ((${#scratch[@]})); then
        rm -f -- "${scratch[@]}"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

new_scratch() {
    local variable=$1
    local path
    path=$(mktemp "${TMPDIR:-/tmp}/irlume-head-gesture.XXXXXX") || die "cannot create scratch file"
    scratch+=("$path")
    printf -v "$variable" '%s' "$path"
}

status_json=
new_scratch status_json
"$status_cmd" status --json --contract 1 >"$status_json" || die "status API failed"
camera_state=$(python3 - "$status_json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 4096:
    raise SystemExit("oversized status document")
doc = json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
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

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
trial_id="$host_label:$service:$expected_gesture:$(date -u +%Y%m%d%H%M%S):$$"

publish_record() {
    local attempt_json=${1:-}
    local capability_outcome=$2
    local resolved_policy=$3
    local output_base
    output_base=$(basename -- "$output")
    output_tmp=$(mktemp "$output_dir/.${output_base}.tmp.XXXXXX") || die "cannot create output temporary"
    python3 - "$validator" "$output" "$output_tmp" "$attempt_json" "$capability_outcome" \
        "$expected_oid" "$expected_binary_sha256" "$host_label" "$service" "$purpose" \
        "$requested_policy" "$resolved_policy" "$trial_id" "$expected_gesture" "$timestamp" <<'PY'
import json
import os
import pathlib
import runpy
import sys

(
    validator_path, output_raw, temporary_raw, attempt_raw, capability_outcome,
    oid, binary_digest, host, service, purpose, requested_policy,
    resolved_policy, trial_id, expected_gesture, timestamp,
) = sys.argv[1:]
validator = runpy.run_path(validator_path)
output = pathlib.Path(output_raw)
temporary = pathlib.Path(temporary_raw)
records = validator["load_records"](output) if output.exists() else []
for index, record in enumerate(records, 1):
    validator["validate_record"](record, index)
if any(record["frozen_commit_oid"] != oid for record in records):
    raise SystemExit("existing evidence has a different frozen OID")
if any(record["release_binary_sha256"] != binary_digest for record in records):
    raise SystemExit("existing evidence has a different binary digest")

zero = {
    "frames": 0, "face_frames": 0, "pitch_range": 0, "yaw_range": 0,
    "pitch_crossings": 0, "yaw_crossings": 0, "mean_step": 0,
}
camera_digest = None
attempt = None
if attempt_raw:
    attempt_path = pathlib.Path(attempt_raw)
    if attempt_path.stat().st_size > 4096:
        raise SystemExit("oversized attempt result")
    attempt = json.loads(
        attempt_path.read_text(encoding="utf-8"),
        object_pairs_hook=validator["object_without_duplicates"],
        parse_constant=validator["reject_constant"],
    )
    expected = {"camera_identity_digest", "typed_outcome", "detector_evidence"}
    if not isinstance(attempt, dict) or set(attempt) != expected:
        raise SystemExit("attempt result has unexpected keys")
    camera_digest = attempt["camera_identity_digest"]

capability = {
    "schema_version": 1,
    "record_type": "capability",
    "frozen_commit_oid": oid,
    "release_binary_sha256": binary_digest,
    "host_label": host,
    "camera_identity_digest": camera_digest,
    "service": "capability",
    "purpose": "capability",
    "requested_policy": "not-applicable",
    "resolved_policy": "not-applicable",
    "trial_id": None,
    "expected_gesture": "none",
    "typed_outcome": capability_outcome,
    "detector_evidence": zero,
    "timestamp": timestamp,
}
existing_capability = [r for r in records if r["record_type"] == "capability" and r["host_label"] == host]
if len(existing_capability) > 1:
    raise SystemExit("duplicate existing host capability")
if existing_capability:
    if existing_capability[0]["typed_outcome"] != capability_outcome:
        raise SystemExit("host capability changed within one matrix")
    if camera_digest is not None and existing_capability[0]["camera_identity_digest"] != camera_digest:
        raise SystemExit("camera identity digest changed within one matrix")
else:
    validator["validate_record"](capability, len(records) + 1)
    records.append(capability)

if attempt is not None:
    record = {
        "schema_version": 1,
        "record_type": "trial",
        "frozen_commit_oid": oid,
        "release_binary_sha256": binary_digest,
        "host_label": host,
        "camera_identity_digest": camera_digest,
        "service": service,
        "purpose": purpose,
        "requested_policy": requested_policy,
        "resolved_policy": resolved_policy,
        "trial_id": trial_id,
        "expected_gesture": expected_gesture,
        "typed_outcome": attempt["typed_outcome"],
        "detector_evidence": attempt["detector_evidence"],
        "timestamp": timestamp,
    }
    validator["validate_record"](record, len(records) + 1)
    if any(r.get("trial_id") == trial_id for r in records):
        raise SystemExit("duplicate generated trial ID")
    records.append(record)

with temporary.open("w", encoding="utf-8", newline="\n") as handle:
    for record in records:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
        handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
os.chmod(temporary, 0o600)
PY
    mv -T -- "$output_tmp" "$output"
    output_tmp=
    python3 - "$output_dir" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

if [[ $camera_state == absent ]]; then
    publish_record "" capability-not-present not-applicable
    printf 'head-gesture-matrix: capability-not-present host=%s\n' "$host_label"
    exit 0
fi

doctor_json=
new_scratch doctor_json
"$doctor_cmd" doctor --json --contract 1 >"$doctor_json" || die "doctor API failed"
python3 - "$doctor_json" <<'PY' || die "doctor reports the camera stack is not ready"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 65536:
    raise SystemExit("oversized doctor document")
doc = json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
checks = doc.get("data", {}).get("checks") if isinstance(doc, dict) and doc.get("ok") is True else None
if not isinstance(checks, list):
    raise SystemExit("invalid doctor envelope")
states = {check.get("id"): check.get("state") for check in checks if isinstance(check, dict)}
required = {"camera-nodes", "models", "stage-detection-model", "stage-recognition-model"}
if any(states.get(check) != "pass" for check in required):
    raise SystemExit("required doctor check did not pass")
PY

read_policy() {
    local variable=$1
    local policy_text policy_value
    policy_text=$("$policy_cmd" credential-release-challenge "$service" status) || die "cannot read service policy"
    case "$policy_text" in
        required|*": REQUIRED "*) policy_value=required ;;
        off|*": off "*) policy_value=off ;;
        *) die "service policy status was not authoritative" ;;
    esac
    printf -v "$variable" '%s' "$policy_value"
}

original_policy=not-applicable
resolved_policy=not-applicable
if [[ $service != gesturecap ]]; then
    read_policy original_policy
    resolved_policy=$original_policy
fi

printf 'head-gesture-matrix: service=%s purpose=%s expected-pose=%s requested-policy=%s\n' \
    "$service" "$purpose" "$expected_gesture" "$requested_policy"
printf 'Type literal ready to begin this bounded attempt: '
IFS= read -r confirmation || die "readiness confirmation ended"
[[ $confirmation == ready ]] || die "literal ready was not received; no attempt started"

if [[ $service != gesturecap && $requested_policy != "$original_policy" ]]; then
    policy_changed=1
    "$policy_cmd" credential-release-challenge "$service" "$requested_policy" --yes >/dev/null || die "cannot set temporary service policy"
    read_policy resolved_policy
    [[ $resolved_policy == "$requested_policy" ]] || die "temporary service policy did not resolve to the requested value"
fi

attempt_json=
new_scratch attempt_json
if ! timeout --foreground 20s "$attempt_cmd" \
    --service "$service" \
    --purpose "$purpose" \
    --expected-gesture "$expected_gesture" \
    --timeout-seconds 20 >"$attempt_json"; then
    die "bounded attempt failed"
fi

publish_record "$attempt_json" capability-present "$resolved_policy"
printf 'head-gesture-matrix: recorded host=%s trial=%s output=%s\n' "$host_label" "$trial_id" "$output"

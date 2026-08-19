#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
    printf 'head-gesture-adapter: %s\n' "$*" >&2
    exit 2
}

declare -A seen=()
preflight=0
service=
purpose=
expected_gesture=
expected_camera_digest=
timeout_seconds=
candidate=
while (($#)); do
    case "$1" in
        --preflight)
            [[ -z ${seen[$1]:-} ]] || die "repeated argument: $1"
            seen[$1]=1
            preflight=1
            shift
            ;;
        --service|--purpose|--expected-gesture|--expected-camera-identity-digest|--timeout-seconds|--candidate-binary)
            (($# >= 2)) || die "missing value for $1"
            [[ -z ${seen[$1]:-} ]] || die "repeated argument: $1"
            seen[$1]=1
            case "$1" in
                --service) service=$2 ;;
                --purpose) purpose=$2 ;;
                --expected-gesture) expected_gesture=$2 ;;
                --expected-camera-identity-digest) expected_camera_digest=$2 ;;
                --timeout-seconds) timeout_seconds=$2 ;;
                --candidate-binary) candidate=$2 ;;
            esac
            shift 2
            ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ $expected_camera_digest =~ ^[0-9a-f]{64}$ ]] || die "invalid expected camera digest"
[[ $candidate =~ ^/proc/[0-9]+/fd/[0-9]+$ && -f $candidate && -x $candidate ]] || die "candidate binary is not a bound executable descriptor"

if ((preflight)); then
    [[ -z $service && -z $purpose && -z $expected_gesture && -z $timeout_seconds ]] || die "preflight received attempt arguments"
    exec env IRLUME_DEV=1 "$candidate" gesturecap identity \
        --expected-camera-identity-digest "$expected_camera_digest"
fi

[[ $service == gesturecap && $purpose == detector ]] || die "only gesturecap detector trials are supported"
case "$expected_gesture" in
    nod|shake|still|look-around|look-down-and-hold) ;;
    *) die "unsupported expected gesture" ;;
esac
[[ $timeout_seconds == 20 ]] || die "attempt timeout does not match the reviewed contract"

root=${IRLUME_HEAD_GESTURE_ROOT:-}
[[ -n $root && -d $root && ! -L $root ]] || die "IRLUME_HEAD_GESTURE_ROOT must name the frozen checkout"
detector=${IRLUME_DET_MODEL:-"$root/models/face_detection_yunet_2023mar.onnx"}
recognizer=${IRLUME_MODEL:-"$root/models/glintr100.onnx"}
mesh=${IRLUME_MESH_MODEL:-"$root/models/face_landmarks_detector.tflite"}
blaze=${IRLUME_BLAZE_MODEL:-"$root/models/blaze_face_short_range.onnx"}

args=(
    gesturecap attempt
    --expected-camera-identity-digest "$expected_camera_digest"
    --expected-gesture "$expected_gesture"
    --det "$detector"
    --model "$recognizer"
    --mesh "$mesh"
    --blaze "$blaze"
    --n 75
)
if [[ -n ${IRLUME_IR_ADAPTER:-} ]]; then
    args+=(--adapter "$IRLUME_IR_ADAPTER")
fi
exec env IRLUME_DEV=1 "$candidate" "${args[@]}"

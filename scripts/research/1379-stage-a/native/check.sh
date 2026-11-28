#!/usr/bin/env bash
set -euo pipefail

die() { printf '%s\n' "$*" >&2; exit 1; }

[[ $# == 4 ]] || die "usage: check.sh UAPI SDK SDK_MANIFEST OUTPUT"
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
uapi=$(realpath -e -- "$1")
sdk=$(realpath -e -- "$2")
manifest=$(realpath -e -- "$3")
out=$(realpath -m -- "$4")
export LC_ALL=C

[[ $out == /tmp/opencode/* ]] || die "output must be under /tmp/opencode"
mkdir -p -- "$out"
[[ -z $(find "$out" -mindepth 1 -print -quit) ]] || die "output directory must be empty"
for header in media.h videodev2.h; do
    [[ -f $uapi/include/linux/$header ]] || die "missing exported Linux $header"
done

private_pc() (
    local root=$1
    [[ -f $root/lib/pkgconfig/libcamera.pc ]] || die "missing private libcamera.pc"
    unset PKG_CONFIG_PATH PKG_CONFIG_SYSROOT_DIR
    export PKG_CONFIG_LIBDIR="$root/lib/pkgconfig"
    [[ $(pkg-config --modversion libcamera) == 0.8.0 ]] || die "unexpected libcamera version"
    [[ $(pkg-config --variable=prefix libcamera) == "$root" ]] || die "wrong SDK prefix"
    [[ $(pkg-config --variable=libdir libcamera) == "$root/lib" ]] || die "wrong SDK library directory"
    [[ $(pkg-config --variable=includedir libcamera) == "$root/include" ]] || die "wrong SDK include directory"
)

libs=$(python3 -B "$here/sdk_manifest.py" "$sdk" "$manifest")
mapfile -t libraries <<< "$libs"
[[ ${#libraries[@]} == 2 ]] || die "expected libcamera and libcamera-base paths"
private_pc "$sdk"

mkdir -- "$out/missing-sdk"
if PKG_CONFIG_PATH="$sdk/lib/pkgconfig" private_pc "$out/missing-sdk" >"$out/private-pc-negative.log" 2>&1; then
    die "private_pc_never_falls_back: incorrectly accepted an ambient package"
fi
grep -Fx 'missing private libcamera.pc' "$out/private-pc-negative.log"

c_args=(-std=c11 -Wall -Wextra -Werror -isystem "$uapi/include" -fsyntax-only)
cxx_args=(-std=c++20 -Wall -Wextra -Werror -O2 -fno-lto -isystem "$sdk/include/libcamera")
reject() {
    local expected=$1 log=$2
    shift 2
    if "$@" >"$log" 2>&1; then
        die "unexpected success: $*"
    fi
    grep -F -- "$expected" "$log"
}

gcc "${c_args[@]}" "$here/linux_uapi.c"
reject 'native IR requires the multiplanar queue' "$out/single-plane-negative.log" \
    gcc "${c_args[@]}" -DCHECK_SINGLE_PLANE "$here/linux_uapi.c"
g++ "${cxx_args[@]}" -c "$here/libcamera_link.cpp" -o "$out/libcamera-link.o"
reject 'static assertion failed: manager stop is void' "$out/manager-stop-negative.log" \
    g++ "${cxx_args[@]}" -DCHECK_MANAGER_STOP_STATUS -fsyntax-only "$here/libcamera_link.cpp"

nm -uC "$out/libcamera-link.o" >"$out/object-references.log"
for symbol in CameraManager::start CameraManager::stop Camera::acquire Camera::release \
              Camera::configure Camera::start Camera::stop Camera::queueRequest FrameBufferAllocator::free; do
    grep -Fq -- "libcamera::$symbol(" "$out/object-references.log" || die "missing link witness: $symbol"
done
reject 'undefined reference to' "$out/missing-library-negative.log" \
    g++ -Wl,-z,defs "$out/libcamera-link.o" -o "$out/unlinked"
grep -Fq 'libcamera::CameraManager::start' "$out/missing-library-negative.log" ||
    die "negative link failed for an unrelated reason"
g++ -Wl,-z,defs,-z,now "$out/libcamera-link.o" "${libraries[@]}" -o "$out/libcamera-link"
readelf -d "$out/libcamera-link" >"$out/dynamic.log"
grep -Eq '\(NEEDED\).*\[libcamera\.so\.0\.8\]' "$out/dynamic.log" ||
    die "linked witness lacks the libcamera dependency"
readelf -d "${libraries[@]}" >>"$out/dynamic.log"
printf '%s\n' 'Native assertions and link passed; link witness not executed.'

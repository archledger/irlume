#!/usr/bin/env bash
set -euo pipefail

die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 2 ]] || die "usage: build_guest.sh CLEAN_LINUX_SOURCE NEW_PRIVATE_BUILD_DIR"
(( EUID != 0 )) || die "build as an ordinary host user"
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
linux=$(realpath -e -- "$1")
out=$(realpath -m -- "$2")
scratch=$(dirname -- "$out")
[[ $scratch == /tmp/opencode/* && $out =~ ^/[A-Za-z0-9._/-]+$ ]] ||
    die "use a new build directory within private /tmp/opencode scratch"
[[ $(git -C "$linux" rev-parse HEAD) == 988117cc1bb17338c586a4e21ade88b5397eac33 ]] ||
    die "wrong Linux source pin"
[[ -z $(git -C "$linux" status --porcelain) ]] || die "Linux source checkout is not clean"
command -v bc >/dev/null || die "provide a verified private bc on PATH"
mkdir -- "$out"
kbuild="$scratch/kbuild"
uapi="$scratch/uapi"
mkdir -p -- "$kbuild"
export LC_ALL=C
unset KCONFIG_CONFIG KBUILD_OUTPUT CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH KCFLAGS KCPPFLAGS
make_args=(-C "$linux" ARCH=x86 O="$kbuild")
make "${make_args[@]}" x86_64_defconfig >"$out/config.log" 2>&1
bash "$linux/scripts/kconfig/merge_config.sh" -m -O "$kbuild" "$kbuild/.config" \
    "$here/kernel.config" >>"$out/config.log" 2>&1
make "${make_args[@]}" olddefconfig >>"$out/config.log" 2>&1
while IFS= read -r setting; do
    if [[ $setting == '# CONFIG_'* ]]; then
        symbol=${setting#\# }
        symbol=${symbol% is not set}
        if grep -q "^${symbol}=" "$kbuild/.config"; then
            die "required disabled symbol changed: $symbol"
        fi
    elif ! grep -Fxq -- "$setting" "$kbuild/.config"; then
        die "missing requested guest setting: $setting"
    fi
done <"$here/kernel.config"
make "${make_args[@]}" -j8 bzImage >"$out/kernel.log" 2>&1 ||
    { tail -40 "$out/kernel.log" >&2; exit 1; }
make "${make_args[@]}" INSTALL_HDR_PATH="$uapi" -j8 headers_install >"$out/uapi.log" 2>&1 ||
    { tail -25 "$out/uapi.log" >&2; exit 1; }

gcc -std=c17 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 -static \
    -isystem "$uapi/include" "$here/guest/init.c" "$here/guest/device_policy.c" -o "$out/init"
readelf -l -d "$out/init" >"$out/guest-elf.txt"
if grep -Eq 'INTERP|NEEDED' "$out/guest-elf.txt"; then die "guest init is not static"; fi
gcc -O2 "$linux/usr/gen_init_cpio.c" -o "$out/gen_init_cpio"
cat >"$out/initramfs.list" <<EOF
dir /dev 755 0 0
dir /proc 755 0 0
dir /sys 755 0 0
dir /run 755 0 0
dir /tmp 700 0 0
nod /dev/console 600 0 0 c 5 1
nod /dev/zero 666 0 0 c 1 5
nod /dev/book2-alias 666 0 0 c 1 5
nod /dev/null 666 0 0 c 1 3
file /init $out/init 755 0 0
EOF
"$out/gen_init_cpio" "$out/initramfs.list" >"$out/initramfs.cpio"
cp -- "$kbuild/arch/x86/boot/bzImage" "$out/bzImage"
cp -- "$kbuild/.config" "$out/guest.config"
(cd -- "$out" && sha256sum bzImage initramfs.cpio >build.sha256)
cat "$out/build.sha256"

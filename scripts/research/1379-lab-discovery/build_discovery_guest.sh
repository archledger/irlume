#!/usr/bin/env bash
# Build the disposable Book 2 discovery guest (B03) from verified inputs.
set -euo pipefail

die() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# == 3 ]] || die "usage: build_discovery_guest.sh CLEAN_LINUX CLEAN_LIBCAMERA NEW_PRIVATE_BUILD_DIR"
(( EUID != 0 )) || die "build as an ordinary host user"
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
boot=$(cd -- "$here/../1379-lab-boot" && pwd -P)
linux=$(realpath -e -- "$1")
libcamera=$(realpath -e -- "$2")
out=$(realpath -m -- "$3")
scratch=$(dirname -- "$out")
[[ $scratch == /tmp/opencode/* && $out =~ ^/[A-Za-z0-9._/-]+$ ]] ||
    die "use a new build directory within private /tmp/opencode scratch"
readonly linux_pin=988117cc1bb17338c586a4e21ade88b5397eac33
readonly libcamera_pin=df8e348d64b4932a0676256ed24f0da3ee9438bc

clean_at() {
    local repo=$1 pin=$2 status
    [[ $(git -C "$repo" rev-parse HEAD) == "$pin" ]] || die "wrong source pin in $repo"
    status=$(git -C "$repo" status --porcelain) || die "could not verify $repo cleanliness"
    [[ -z $status ]] || die "$repo checkout is not clean"
}
clean_at "$linux" "$linux_pin"
clean_at "$libcamera" "$libcamera_pin"
[[ $(git -C "$libcamera" describe --exact-match HEAD) == v0.8.0 ]] || die "libcamera is not the real v0.8.0 tag"
command -v bc >/dev/null || die "provide a verified private bc on PATH"
mkdir -- "$out"
export LC_ALL=C
unset KCONFIG_CONFIG KBUILD_OUTPUT CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH KCFLAGS KCPPFLAGS

# Hardlinked copy of the pinned tree plus the guest-only driver. Changed
# files are replaced by rename so the pinned checkout's inodes never change.
src="$scratch/linux-b03"
rm -rf -- "$src"
cp -al -- "$linux" "$src"
rm -rf -- "$src/.git"
tdir="$src/drivers/media/test-drivers"
mkdir -- "$tdir/book2-lab-sim"
cp -- "$here"/kernel/book2-lab-sim/{book2_lab_sim.c,Kconfig,Makefile} "$tdir/book2-lab-sim/"
awk '{ print } /^source "drivers\/media\/test-drivers\/visl\/Kconfig"$/ {
    print "source \"drivers/media/test-drivers/book2-lab-sim/Kconfig\"" }' \
    "$tdir/Kconfig" >"$tdir/Kconfig.new"
mv -- "$tdir/Kconfig.new" "$tdir/Kconfig"
# shellcheck disable=SC2016 # literal Makefile text
{ cat -- "$tdir/Makefile"; echo 'obj-$(CONFIG_VIDEO_BOOK2_LAB_SIM) += book2-lab-sim/'; } >"$tdir/Makefile.new"
mv -- "$tdir/Makefile.new" "$tdir/Makefile"
cp -- "$linux/.git/index" "$scratch/linux-b03.index"
status=$(GIT_INDEX_FILE="$scratch/linux-b03.index" git --git-dir="$linux/.git" --work-tree="$src" \
    status --porcelain --untracked-files=all)
expected=$' M drivers/media/test-drivers/Kconfig\n M drivers/media/test-drivers/Makefile\n?? drivers/media/test-drivers/book2-lab-sim/Kconfig\n?? drivers/media/test-drivers/book2-lab-sim/Makefile\n?? drivers/media/test-drivers/book2-lab-sim/book2_lab_sim.c'
[[ $status == "$expected" ]] || die "unexpected guest kernel tree changes: $status"
printf '%s\n' "$status" >"$out/kernel-tree.status"

kbuild="$scratch/kbuild-b03"
uapi="$scratch/uapi-b03"
mkdir -p -- "$kbuild"
make_args=(-C "$src" ARCH=x86 O="$kbuild")
make "${make_args[@]}" x86_64_defconfig >"$out/config.log" 2>&1
bash "$src/scripts/kconfig/merge_config.sh" -m -O "$kbuild" "$kbuild/.config" \
    "$here/kernel-discovery.config" >>"$out/config.log" 2>&1
make "${make_args[@]}" olddefconfig >>"$out/config.log" 2>&1
while IFS= read -r setting; do
    if [[ $setting == '# CONFIG_'* ]]; then
        symbol=${setting#\# }
        symbol=${symbol% is not set}
        if grep -q "^${symbol}=" "$kbuild/.config"; then die "required disabled symbol changed: $symbol"; fi
    elif ! grep -Fxq -- "$setting" "$kbuild/.config"; then
        die "missing requested guest setting: $setting"
    fi
done <"$here/kernel-discovery.config"
make "${make_args[@]}" -j12 bzImage >"$out/kernel.log" 2>&1 || { tail -40 "$out/kernel.log" >&2; exit 1; }
make "${make_args[@]}" INSTALL_HDR_PATH="$uapi" -j12 headers_install >"$out/uapi.log" 2>&1 ||
    { tail -25 "$out/uapi.log" >&2; exit 1; }
status=$(git -C "$linux" status --porcelain) || die "could not recheck the pinned Linux checkout"
[[ -z $status ]] || die "pinned Linux checkout changed during the build"

strict_c=(gcc -std=c17 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 -isystem "$uapi/include")
strict_cxx=(g++ -std=c++20 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 -isystem "$uapi/include")
"${strict_c[@]}" -c "$boot/guest/cgroup_device.c" -o "$out/cgroup_device.o"
"${strict_cxx[@]}" -static -I "$boot/guest" "$here/guest/discovery_supervisor.cpp" \
    "$out/cgroup_device.o" -o "$out/supervisor"
readelf -l -d "$out/supervisor" >"$out/supervisor-elf.txt"
if grep -Eq 'INTERP|NEEDED' "$out/supervisor-elf.txt"; then die "supervisor is not static"; fi

gcc -O2 "$linux/usr/gen_init_cpio.c" -o "$out/gen_init_cpio"
cat >"$out/lab.list" <<EOF
dir /dev 755 0 0
dir /proc 755 0 0
dir /sys 755 0 0
dir /run 755 0 0
dir /tmp 700 0 0
nod /dev/console 600 0 0 c 5 1
file /init $out/supervisor 755 0 0
EOF
"$out/gen_init_cpio" "$out/lab.list" >"$out/lab.cpio"
cp -- "$kbuild/arch/x86/boot/bzImage" "$out/bzImage"
cp -- "$kbuild/.config" "$out/guest.config"
(cd -- "$here" && sha256sum kernel-discovery.config build_discovery_guest.sh \
    kernel/book2-lab-sim/* guest/* contract/* >"$out/inputs.sha256")
(cd -- "$boot" && sha256sum guest/cgroup_device.c guest/lab.h >>"$out/inputs.sha256")
(cd -- "$out" && sha256sum bzImage lab.cpio >build.sha256)
cat "$out/build.sha256"

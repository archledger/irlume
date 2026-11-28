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
"${strict_cxx[@]}" -static -I "$boot/guest" -I "$here/lab" "$here/guest/discovery_supervisor.cpp" \
    "$here/lab/lab_contract.cpp" "$out/cgroup_device.o" -o "$out/supervisor"
readelf -l -d "$out/supervisor" >"$out/supervisor-elf.txt"
"${strict_c[@]}" -static "$here/guest/ir_stub.c" -o "$out/ir-stub"
if grep -Eq 'INTERP|NEEDED' "$out/supervisor-elf.txt"; then die "supervisor is not static"; fi

# libcamera sees only gnutls, yaml-0.1 and the .pc files they require.
: "${MESON:?set MESON to the verified Meson 1.9.1 binary}"
[[ $("$MESON" --version) == 1.9.1 ]] || die "Meson 1.9.1 required"
for tool in ninja openssl readelf pacman pkg-config; do
    command -v "$tool" >/dev/null || die "missing build tool: $tool"
done
pkgview="$scratch/pkgconfig-view"
rm -rf -- "$pkgview"
mkdir -- "$pkgview"
declare -A seen=()
queue=(gnutls yaml-0.1)
while ((${#queue[@]})); do
    module=${queue[0]}
    queue=("${queue[@]:1}")
    [[ -z ${seen[$module]:-} ]] || continue
    seen[$module]=1
    pcdir=$(pkg-config --variable=pcfiledir "$module") || die "missing pkg-config module $module"
    ln -s -- "$pcdir/$module.pc" "$pkgview/$module.pc"
    while read -r dep _; do
        [[ -z $dep ]] || queue+=("$dep")
    done < <(pkg-config --print-requires --print-requires-private "$module")
done
ls "$pkgview" >"$out/pkgconfig-view.txt"

build_libcamera() {
    local name=$1 source=$2
    local bdir="$scratch/lc-$name-build" stage="$scratch/lc-$name-stage" lib
    rm -rf -- "$bdir" "$stage"
    PATH="$(dirname -- "$MESON"):$PATH" PKG_CONFIG_LIBDIR="$pkgview" PKG_CONFIG_PATH='' \
        "$MESON" setup "$bdir" "$source" --prefix=/usr --buildtype=debugoptimized --wrap-mode=nodownload \
        -Dpipelines=ipu3 -Dipas=ipu3 -Dudev=disabled -Dlibdw=disabled -Dlibunwind=disabled \
        -Dtracing=disabled -Dcam=disabled -Dqcam=disabled -Dgstreamer=disabled -Dv4l2=disabled \
        -Dpycamera=disabled -Dlc-compliance=disabled -Ddocumentation=disabled -Dtest=false \
        -Dandroid=disabled >"$out/lc-$name-setup.log" 2>&1 || { tail -30 "$out/lc-$name-setup.log" >&2; exit 1; }
    grep -Eq 'IPA modules signed with[[:space:]]*:[[:space:]]*gnutls' "$out/lc-$name-setup.log" ||
        die "$name libcamera does not sign IPA modules with gnutls"
    PATH="$(dirname -- "$MESON"):$PATH" "$MESON" compile -C "$bdir" >"$out/lc-$name-compile.log" 2>&1 ||
        { tail -30 "$out/lc-$name-compile.log" >&2; exit 1; }
    PATH="$(dirname -- "$MESON"):$PATH" DESTDIR="$stage" "$MESON" install -C "$bdir" --strip \
        >"$out/lc-$name-install.log" 2>&1 || { tail -30 "$out/lc-$name-install.log" >&2; exit 1; }
    lib="$stage/usr/lib/libcamera.so.0.8"
    [[ -f $lib && -f $stage/usr/lib/libcamera/ipa/ipa_ipu3.so.sign ]] || die "$name libcamera install incomplete"
    if readelf -dW "$lib" | grep -Eq '\((RUNPATH|RPATH)\)'; then die "$name libcamera keeps a build rpath"; fi
    find "$stage" -type f -exec sh -c 'head -c4 "$1" | grep -q ELF && readelf -dW "$1"' _ {} \; \
        >"$out/lc-$name-dynamic.txt"
    if grep -Eq 'NEEDED.*(libudev|libdw|libunwind|lttng)' "$out/lc-$name-dynamic.txt"; then
        die "$name libcamera links a disabled optional dependency"
    fi
    "${strict_cxx[@]}" -I "$stage/usr/include/libcamera" "$here/guest/discovery_worker.cpp" \
        -L "$stage/usr/lib" -lcamera -lcamera-base -o "$out/worker-$name"
}

lc_stock="$scratch/libcamera-stock"
rm -rf -- "$lc_stock"
git clone -q --shared --no-checkout -- "$libcamera" "$lc_stock"
git -C "$lc_stock" checkout -q --detach "$libcamera_pin"
[[ $(git -C "$lc_stock" describe --exact-match HEAD) == v0.8.0 ]] || die "stock clone lost the v0.8.0 tag"
build_libcamera stock "$lc_stock"

# Lab libcamera: the pinned tree plus the lab files and one reviewed patch.
lc_lab="$scratch/libcamera-lab"
rm -rf -- "$lc_lab"
git clone -q --shared --no-checkout -- "$libcamera" "$lc_lab"
git -C "$lc_lab" checkout -q --detach "$libcamera_pin"
mkdir -- "$lc_lab/src/libcamera/lab"
cp -- "$here"/lab/{lab_contract.h,lab_contract.cpp,discovery_requests.h} "$here"/libcamera/{lab_guard.h,lab_guard.cpp} \
    "$lc_lab/src/libcamera/lab/"
git -C "$lc_lab" apply -- "$here/libcamera/book2-lab.patch"
status=$(git -C "$lc_lab" status --porcelain --untracked-files=all)
expected=$' M include/libcamera/internal/ipa_manager.h\n M include/libcamera/internal/media_device.h\n M include/libcamera/internal/v4l2_device.h\n M src/libcamera/ipa_manager.cpp\n M src/libcamera/media_device.cpp\n M src/libcamera/media_object.cpp\n M src/libcamera/meson.build\n M src/libcamera/pipeline/ipu3/ipu3.cpp\n M src/libcamera/v4l2_device.cpp\n?? src/libcamera/lab/discovery_requests.h\n?? src/libcamera/lab/lab_contract.cpp\n?? src/libcamera/lab/lab_contract.h\n?? src/libcamera/lab/lab_guard.cpp\n?? src/libcamera/lab/lab_guard.h'
[[ $status == "$expected" ]] || die "unexpected lab libcamera tree changes: $status"
printf '%s\n' "$status" >"$out/libcamera-lab-tree.status"
build_libcamera lab "$lc_lab"

# Runtime closure from NEEDED entries, resolved in /usr/lib without running anything.
closure() {
    python3 - "$1" "$2" <<'PY'
import os, re, subprocess, sys
stage, worker = sys.argv[1:3]
def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout
names, elfs = set(), [worker]
for top, _, files in os.walk(os.path.join(stage, "usr")):
    for f in files:
        path = os.path.join(top, f)
        names.add(f)
        if not os.path.islink(path):
            with open(path, "rb") as h:
                if h.read(4) == b"\x7fELF":
                    elfs.append(path)
host, todo = {}, list(elfs)
while todo:
    for name in re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", run("readelf", "-dW", todo.pop())):
        if name in names or name in host:
            continue
        src = os.path.join("/usr/lib", name)
        if not os.path.isfile(src):
            sys.exit(f"unresolved shared library {name}")
        host[name] = os.path.realpath(src)
        todo.append(host[name])
interp = re.search(r"interpreter: ([^\]]+)\]", run("readelf", "-lW", worker)).group(1)
print(f"interp {interp} {os.path.realpath(interp)}")
for name, real in sorted(host.items()):
    print(f"lib {name} {real}")
PY
}

# gen_init_cpio list: base layout, supervisor as /init, then optional worker,
# staged libcamera (no headers or pkg-config) and the host closure.
image_list() {
    python3 - "$@" <<'PY'
import os, sys
supervisor, worker, stage, closure = sys.argv[1:5]
out = ["dir /dev 755 0 0", "dir /proc 755 0 0", "dir /sys 755 0 0", "dir /run 755 0 0",
       "dir /tmp 700 0 0", "dir /etc 755 0 0", "nod /dev/console 600 0 0 c 5 1",
       f"file /init {supervisor} 755 0 0"]
if worker != "-":
    out += ["dir /lab 755 0 0", f"file /lab/discovery-worker {worker} 755 0 0"]
staged = set()
if stage != "-":
    root = os.path.join(stage, "usr")
    for top, dirs, files in os.walk(root):
        rel = os.path.relpath(top, stage)
        dirs[:] = sorted(d for d in dirs if os.path.join(rel, d) not in ("usr/include", "usr/lib/pkgconfig"))
        out.append(f"dir /{rel} 755 0 0")
        for f in sorted(files):
            path = os.path.join(top, f)
            staged.add(f"/{rel}/{f}")
            if os.path.islink(path):
                out.append(f"slink /{rel}/{f} {os.readlink(path)} 777 0 0")
            else:
                mode = "755" if os.access(path, os.X_OK) else "644"
                out.append(f"file /{rel}/{f} {path} {mode} 0 0")
if closure != "-":
    for line in open(closure):
        kind, name, real = line.split()
        if kind == "interp":
            out += ["dir /lib64 755 0 0", f"slink {name} {real} 777 0 0"]
            name = os.path.basename(real)
        if f"/usr/lib/{name}" not in staged:
            staged.add(f"/usr/lib/{name}")
            out.append(f"file /usr/lib/{name} {real} 755 0 0")
print("\n".join(out))
PY
}

record_host_libs() {
    local list=$1 kind name real pkg
    while read -r kind name real; do
        pkg=$(pacman -Qoq -- "$real") || die "host library $real is not owned by a package"
        printf '%s %s %s %s\n' "$(sha256sum -- "$real" | cut -d' ' -f1)" "$(pacman -Q -- "$pkg")" "$kind" "$real"
    done <"$list"
}

for name in stock lab; do
    closure "$scratch/lc-$name-stage" "$out/worker-$name" >"$out/closure-$name.txt"
    record_host_libs "$out/closure-$name.txt" >"$out/host-libs-$name.txt"
done
sha256sum -- "$scratch/lc-lab-stage/usr/lib/libcamera/ipa/ipa_ipu3.so" | cut -d' ' -f1 >"$out/ipa_ipu3.sha256"

gcc -O2 "$linux/usr/gen_init_cpio.c" -o "$out/gen_init_cpio"
image_list "$out/supervisor" "$out/worker-lab" "$scratch/lc-lab-stage" "$out/closure-lab.txt" >"$out/lab.list"
printf '%s\n' "file /lab/front.contract $here/contract/front.contract 644 0 0" \
    "file /lab/ipa_ipu3.sha256 $out/ipa_ipu3.sha256 644 0 0" "file /lab/ir-stub $out/ir-stub 755 0 0" \
    >>"$out/lab.list"
"$out/gen_init_cpio" "$out/lab.list" >"$out/lab.cpio"
image_list "$out/supervisor" "$out/worker-stock" "$scratch/lc-stock-stage" "$out/closure-stock.txt" \
    >"$out/stock.list"
"$out/gen_init_cpio" "$out/stock.list" >"$out/stock.cpio"
cp -- "$kbuild/arch/x86/boot/bzImage" "$out/bzImage"
cp -- "$kbuild/.config" "$out/guest.config"
(cd -- "$here" && sha256sum kernel-discovery.config build_discovery_guest.sh \
    kernel/book2-lab-sim/* guest/* lab/* libcamera/* contract/* >"$out/inputs.sha256")
(cd -- "$boot" && sha256sum guest/cgroup_device.c guest/lab.h >>"$out/inputs.sha256")
(cd -- "$out" && sha256sum bzImage lab.cpio stock.cpio >build.sha256)
cat "$out/build.sha256"

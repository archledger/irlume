#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
src="$tmp/source"
mkdir -p "$src/packaging/debian" "$src/scripts" "$src/models" "$tmp/bin" "$tmp/out"
cp -- "$repo/packaging/debian/build-deb-container.sh" "$src/packaging/debian/"
for name in container-build.sh bookworm-snapshot.sources; do
    if [ -f "$repo/packaging/debian/$name" ]; then
        cp -- "$repo/packaging/debian/$name" "$src/packaging/debian/"
    fi
done
printf 'test CA fixture\n' > "$tmp/ca.pem"
mkdir "$tmp/model-cache"
printf 'pinned model\n' > "$tmp/model-cache/model.onnx"
(cd "$tmp/model-cache" && sha256sum model.onnx > "$src/models/SHA256SUMS")
printf 'test-only source\n' > "$src/Cargo.lock"
cat > "$src/scripts/fetch-models.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../models"
if [[ ! -f model.onnx ]]; then
    printf 'pinned model\n' > model.onnx
    # A restrictive staging default ACL can mask out read access.
    chmod 0600 model.onnx
fi
sha256sum --quiet -c SHA256SUMS
EOF
printf '/target/\n/models/*.onnx\n' > "$src/.gitignore"
git -C "$src" init -q
git -C "$src" config tar.umask 0077
printf 'Cargo.lock export-ignore\n' > "$tmp/global-attributes"
git -C "$src" config core.attributesFile "$tmp/global-attributes"
git -C "$src" add .
GIT_AUTHOR_DATE='@1700000000 +0000' GIT_COMMITTER_DATE='@1700000000 +0000' \
    git -C "$src" -c user.name=Fixture -c user.email=fixture@example.invalid \
    -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm fixture
mkdir "$src/target"
cp -- "$tmp/model-cache/model.onnx" "$src/models/"
touch "$src/target/stale-binary" "$src/host-only.txt" "$src/models/unlisted.onnx"

cat > "$tmp/bin/podman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$CALLS"
for arg; do
    case "$arg" in
        *:/src:ro,z) source=${arg%:/src:ro,z} ;;
        *:/tmp/irlume-source.tar:ro,z) archive=${arg%:/tmp/irlume-source.tar:ro,z} ;;
        *:/tmp/irlume-ca.pem:ro,z) ca=${arg%:/tmp/irlume-ca.pem:ro,z} ;;
        *:/out:z) out=${arg%:/out:z} ;;
    esac
done
test -n "${source:-}"
test -n "${archive:-}"
test -f "$source/Cargo.lock"
test ! -e "$source/.git"
test ! -e "$source/target"
test ! -e "$source/host-only.txt"
test ! -e "$source/models/unlisted.onnx"
test -f "$source/packaging/debian/bookworm-snapshot.sources"
test "$(stat -c %a "$source/models/model.onnx")" = 644
test "$(tar -tvf "$archive" Cargo.lock | cut -c1-10)" = '-rw-r--r--'
(cd "$source/models" && sha256sum --quiet -c SHA256SUMS)
test -n "${ca:-}"
cmp "$CA_BUNDLE" "$ca"
test -n "${out:-}"
test "$out" != "$OUT"
printf 'fixture package\n' > "$out/irlume_0.0.0_amd64.deb"
EOF
chmod +x "$tmp/bin/podman"
export PATH="$tmp/bin:$PATH" CALLS="$tmp/podman-args" CA_BUNDLE="$tmp/ca.pem" OUT="$tmp/out"
unset SOURCE_DATE_EPOCH
builder="$src/packaging/debian/build-deb-container.sh"

for invalid in '' -1 '123; exit 0' 1000000000000; do
    if SOURCE_DATE_EPOCH="$invalid" bash "$builder" > "$tmp/invalid.log" 2>&1; then
        echo 'FAIL: invalid SOURCE_DATE_EPOCH accepted' >&2
        exit 1
    fi
    grep -F 'invalid SOURCE_DATE_EPOCH' "$tmp/invalid.log" || { cat "$tmp/invalid.log" >&2; exit 1; }
    test ! -e "$CALLS"
done

printf 'dirty\n' >> "$src/Cargo.lock"
if bash "$builder" > "$tmp/dirty.log" 2>&1; then
    echo 'FAIL: dirty tracked source accepted' >&2
    exit 1
fi
grep -F 'tracked changes' "$tmp/dirty.log"
test ! -e "$CALLS"
git -C "$src" show HEAD:Cargo.lock > "$src/Cargo.lock"

(umask 077; bash "$builder")
grep -Fx 'SOURCE_DATE_EPOCH=1700000000' "$CALLS"
grep -Fx 'linux/amd64' "$CALLS"
grep -Fx 'NFPM_SHA256=3f1cf344bd0b57373ca55636a78c08b0491f7293d609a456a9ac3b0b150fda97' "$CALLS"
grep -Fx '/src/packaging/debian/container-build.sh' "$CALLS"
grep -Fx 'fixture package' "$OUT/irlume_0.0.0_amd64.deb"
rm -- "$src/models/model.onnx"
(umask 077; SOURCE_DATE_EPOCH=1700000010 bash "$builder")
grep -Fx 'SOURCE_DATE_EPOCH=1700000010' "$CALLS"

rm -- "$CALLS"
printf 'Cargo.lock export-ignore\n' > "$src/.git/info/attributes"
if bash "$builder" > "$tmp/attributes.log" 2>&1; then
    echo 'FAIL: local archive attributes accepted' >&2
    exit 1
fi
grep -F 'local Git attributes' "$tmp/attributes.log"
test ! -e "$CALLS"
echo 'PASS: Debian builder rejects bad epoch, tracked drift and local archive attributes.'

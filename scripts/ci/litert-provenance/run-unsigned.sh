#!/usr/bin/env bash
# Private pre-signing build driver for the previously verified review bundle.
set -euo pipefail
umask 077
[[ $# == 2 ]]
if [[ ! -d $1/bundle || ! -d $1/packages || ! -f $1/storage.conf ]]; then
  printf '%s\n' 'Reviewed input provisioning is not ready; refusing the unsigned build.' >&2
  exit 78
fi
staged=$(realpath -e -- "$1")
out=$(realpath -m -- "$2")
tools=$(realpath -e -- "$(dirname -- "$0")")
capsule=litert-jammy-toolchain-replay.tar.gz
command -v python3 jq podman tar >/dev/null
read_pin() {
  jq -er --arg role "$1" '.[$role] | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$tools/reviewed-inputs.json"
}
# Read pins beside the reviewed checkout, never from the provisioned bundle.
pin=$(read_pin reviewedManifestSha256)
capsule_sha=$(read_pin toolchainArchiveSha256)
source_sha=$(read_pin sourceArchiveSha256)
elf=$(read_pin runtimeSha256)
python3 -E -B "$tools/verify_delivery.py" "$staged/bundle" --trusted-review-manifest-sha256 "$pin"
printf '%s  %s\n' "$capsule_sha" "$staged/bundle/$capsule" | sha256sum --check --strict --quiet
printf '%s  %s\n' "$source_sha" "$staged/bundle/runtime-rebuild-inputs-fixture-trim-private.tar.zst" \
  | sha256sum --check --strict --quiet
mkdir -m 0700 -- "$out" "$out/recipe"
tar --no-same-owner --no-same-permissions -xf "$staged/bundle/$capsule" -C "$out/recipe"
export CONTAINERS_STORAGE_CONF="$staged/storage.conf"
bash "$out/recipe/replay-local.sh" "$staged/bundle" "$staged/packages" "$out/replay"
rebuilt=$out/replay/run/build-runtime/libtensorflowlite_c.so
read -r actual _ < <(sha256sum "$rebuilt")
[[ $actual == "$elf" ]]
jq -n --arg elf "$actual" --arg source "$source_sha" --arg capsule "$capsule_sha" --arg manifest "$pin" \
  '{
    format: "irlume-litert-unsigned-rebuild-receipt-v1",
    attestationStatus: "unsigned-private-draft",
    subject: {name: "libtensorflowlite_c.so", sha256: $elf},
    materials: {sourceArchiveSha256: $source, toolchainArchiveSha256: $capsule, reviewedManifestSha256: $manifest},
    buildNetwork: "none",
    result: "byte-identical"
  }' > "$out/unsigned-build-receipt.json"

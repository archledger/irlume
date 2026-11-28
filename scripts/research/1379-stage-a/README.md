# Book 2 interface proof (Stage A)

This private research tool does not enumerate, open, configure or capture from a
camera. It does not construct a libcamera manager or run its IPU3 pipeline or
IPA. No Irlume binary, service, configuration, PAM stack, credential or device is
changed by the proof.

## Private build inputs

Use an ordinary x86-64 Linux account and a fresh `scratch` directory under
`/tmp/opencode`. Obtain clean source checkouts of
[Linux `988117cc`](https://github.com/gregkh/linux/tree/988117cc1bb17338c586a4e21ade88b5397eac33)
and [libcamera `df8e348d`](https://github.com/libcamera-org/libcamera/tree/df8e348d64b4932a0676256ed24f0da3ee9438bc).
Verify both exact commits before build. The libcamera checkout must have the
upstream `v0.8.0` tag pointing at that exact commit. Fetch the tag and confirm
`git -C "$libcamera" describe --exact-match HEAD` prints `v0.8.0`: a shallow
checkout without the tag can report the wrong runtime string despite the
correct `.pc` version. Use the pinned tree's `headers_install`, not the host's
Linux UAPI. With GNU Make, GCC, Ninja and the verified private Meson environment
on `PATH`, from a clean build environment:

```sh
mkdir "$scratch/kbuild"
make -C "$linux" ARCH=x86 O="$scratch/kbuild" \
    INSTALL_HDR_PATH="$scratch/uapi" headers_install
unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR PKG_CONFIG_SYSROOT_DIR LD_LIBRARY_PATH
meson setup "$scratch/lc-build" "$libcamera" --prefix "$scratch/sdk" --libdir lib \
    --wrap-mode=nodownload -Dpipelines=ipu3 -Dipas=ipu3 -Dtest=false \
    -Dcam=disabled -Dqcam=disabled -Dgstreamer=disabled -Ddocumentation=disabled \
    -Dpycamera=disabled -Dlc-compliance=disabled -Dv4l2=disabled -Dtracing=disabled
meson compile -C "$scratch/lc-build"
meson install -C "$scratch/lc-build" --no-rebuild
```

The reference build used Meson 1.9.1, Jinja2 3.1.6, MarkupSafe 3.0.3, ply 3.11
and PyYAML 6.0.3 in scratch. Verify the wheel hashes against the corresponding
published files before use. Retain tool versions, Meson options, both source
commits and the artifact receipt, not IPA build keys. Do not stage a system
library or generate the receipt from a substitute SDK.

```sh
(
    cd "$scratch/sdk"
    find include lib -type f \( -name '*.h' -o -name '*.pc' \
        -o -name 'libcamera*.so.*' -o -name 'ipa_ipu3.so' \
        -o -name 'ipa_ipu3.so.sign' \) -print0 |
        sort -z | xargs -0 sha256sum
) > "$scratch/sdk.sha256"
bash scripts/research/1379-stage-a/native/check.sh \
    "$scratch/uapi" "$scratch/sdk" "$scratch/sdk.sha256" "$scratch/native"
```

The check requires positive compilation and linking plus deliberate
single-planar, wrong C++ signature, omitted-library and ambient pkg-config
failures. It clears ambient compiler include overrides and records actual GCC
header traces, refusing Linux or libcamera headers outside the verified roots.
It records the linked executable hash without running `libcamera-link`.
Header and link success say nothing about the reporter's loaded modules,
ownership of the media graphs, safe teardown or optical OFF.

## Isolated link and fixture run

Use Rust 1.88.0, Python 3 and bubblewrap with user and network namespaces.
The following selects the current unit-test executable from Cargo's
`--no-run` output and records its hash. Neither executable runs on the host.

```sh
here=scripts/research/1379-stage-a
mkdir -p "$scratch/rust-target"
fixture=$(python3 -B "$here/fixture_build.py" "$scratch/rust-target")
python3 -B "$here/run_isolated.py" "$scratch/sdk" "$scratch/sdk.sha256" \
    "$scratch/native/libcamera-link" "$fixture"
```

The inputs and receipts must belong to the just-verified private build. The
runner checks the SDK and both executable receipts. It mounts only the two
approved library files and expected witness or test executable, refuses host
fallback, and requires the exact named Stage A test set. These receipts are
for trusted scratch, not proof against a writer that can replace both artifacts
and receipts. The witness reads the runtime version without starting a manager
or handler. Both synthetic capture orders and negative teardown cases run in
the Rust test binary. Its scratch marker persists across an actual
child exit and reopen; that is not a power-loss or rollback-resistance result.
Each case directory is removed when the test that made it ends, and a name
left by an earlier process with the same PID is skipped.
The synthetic `ip3y` checks establish layout and payload bounds, not receiver
completeness, device identity, ownership, optical state or authorization.

Run the wrapper and manifest tests with:

```sh
python3 -B -m unittest discover -s "$here" -p 'test_run_isolated.py'
python3 -B -m unittest discover -s "$here/native" -p 'test_sdk_manifest.py'
```

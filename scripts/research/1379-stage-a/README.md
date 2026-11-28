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
Verify both exact commits before build. Use the pinned tree's `headers_install`,
not the host's Linux UAPI. With GNU Make, GCC, Ninja and the verified private
Meson environment on `PATH`, from a clean build environment:

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
failures. It does not execute the resulting `libcamera-link` executable.
Header and link success say nothing about the reporter's loaded modules,
ownership of the media graphs, safe teardown or optical OFF.

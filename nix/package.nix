## irlume, built from source with buildRustPackage.
##
## Produces $out/bin/{irlume,irlumed}, the PAM module at
## $out/lib/security/pam_irlume.so, and the shipped ONNX weights under
## $out/share/irlume/models/. The NixOS module (nix/module.nix) points the
## daemon's IRLUME_*_MODEL env vars at that share dir, so nothing is copied
## into /etc on a Nix system.
##
## onnxruntime is NOT a build dependency: the `ort` crate uses load-dynamic,
## so libonnxruntime.so is only needed to run. The module supplies it via
## ORT_DYLIB_PATH (the pinned 1.24.4 build from the flake); nixpkgs' own
## onnxruntime is older than irlume's 1.24 floor and deadlocks at load.
{
  lib,
  rustPlatform,
  pkg-config,
  clang,
  tpm2-tss,
  linux-pam,
  linuxHeaders,
  # Source tree. The flake passes `self`; a plain `nix-build` falls back to a
  # cleaned copy of the repo root (drops target/ and .git, keeps the LFS-pulled
  # models/ which the package installs).
  src ? lib.cleanSource ../.,
}:

rustPlatform.buildRustPackage {
  pname = "irlume";
  version = "0.3.0";
  inherit src;

  # Vendored via importCargoLock. The two tss-esapi crates come from our
  # fork (branch irlume-patches, rev 7567f60); everything else is crates.io.
  # Both git crates share one repo/rev, so importCargoLock fetches it once and
  # both keys carry the same hash. Bump both hashes together when Cargo.lock
  # moves the fork rev (nix build prints the correct hash on mismatch).
  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "tss-esapi-7.7.0" = "sha256-DMSoJtwvVIUK++Ych15C6EM0hMk15w5oEAkUQoWhJ+A=";
      "tss-esapi-sys-0.6.0" = "sha256-DMSoJtwvVIUK++Ych15C6EM0hMk15w5oEAkUQoWhJ+A=";
    };
  };

  nativeBuildInputs = [
    pkg-config
    clang
    rustPlatform.bindgenHook # sets LIBCLANG_PATH and the bindgen clang args
  ];

  buildInputs = [
    tpm2-tss # tss-esapi links tss2-*
    linux-pam # the PAM cdylib links libpam
  ];

  # v4l2-sys-mit's bindgen parses <linux/videodev2.h>; hand clang the kernel
  # UAPI headers. bindgenHook already exports the base args, so append.
  preBuild = ''
    export BINDGEN_EXTRA_CLANG_ARGS="$BINDGEN_EXTRA_CLANG_ARGS -isystem ${linuxHeaders}/include"
  '';

  # The suite needs a camera, a TPM, and PAM; none exist in the sandbox.
  # The workflow gates those behind hardware and runs unit tests elsewhere.
  doCheck = false;

  # buildRustPackage installs the two bins to $out/bin. The PAM cdylib and the
  # model weights are not bins, so place them here.
  postInstall = ''
    install -Dm0755 \
      "$(find target -name libpam_irlume.so -print -quit)" \
      "$out/lib/security/pam_irlume.so"

    install -d "$out/share/irlume/models"
    install -m0644 models/*.onnx "$out/share/irlume/models/"
  '';

  meta = {
    description = "Windows Hello-style IR face login for Linux";
    homepage = "https://github.com/archledger/irlume";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
    mainProgram = "irlume";
  };
}

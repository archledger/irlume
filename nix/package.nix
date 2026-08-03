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
  fetchurl,
  runCommand,
  # Source tree. The flake passes `self`; a plain `nix-build` falls back to a
  # cleaned copy of the repo root (drops target/ and .git).
  src ? lib.cleanSource ../.,
  # The ONNX model weights are NOT in the source tree (moved out of Git LFS so
  # builds do not consume the account's LFS bandwidth quota); fetch them by hash
  # from the models-v1 release. A directory of the four *.onnx files that
  # postInstall copies into the result. Keep these hashes in step with
  # models/SHA256SUMS (nix prints the correct hash on a mismatch).
  models ?
    runCommand "irlume-models" {
      glintr100 = fetchurl {
        url = "https://github.com/archledger/irlume/releases/download/models-v1/glintr100.onnx";
        sha256 = "a7933ea5330113b01c9b60351d8f4c33003f145d8470ac5f0e52ee2effe25c60";
      };
      yunet = fetchurl {
        url = "https://github.com/archledger/irlume/releases/download/models-v1/face_detection_yunet_2023mar.onnx";
        sha256 = "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4";
      };
      landmark = fetchurl {
        url = "https://github.com/archledger/irlume/releases/download/models-v1/face_landmark.onnx";
        sha256 = "821683be088447839638f79d64268bd501bdb72e5d9e262ec981c7e252956caf";
      };
      blaze = fetchurl {
        url = "https://github.com/archledger/irlume/releases/download/models-v1/blaze_face_short_range.onnx";
        sha256 = "c5453678015f6289c1d77bda88a8ba9c87574f01de1a05ba1909b9a7e08b237b";
      };
    } ''
      mkdir -p "$out"
      cp "$glintr100" "$out/glintr100.onnx"
      cp "$yunet" "$out/face_detection_yunet_2023mar.onnx"
      cp "$landmark" "$out/face_landmark.onnx"
      cp "$blaze" "$out/blaze_face_short_range.onnx"
    '',
}:

rustPlatform.buildRustPackage {
  pname = "irlume";
  # Derive from Cargo.toml so it never lags the released version (it had gone
  # stale at 0.4.0). The workspace crates all use version.workspace = true.
  version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version;
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

    # KDE wallet handoff helper. buildRustPackage puts every bin in $out/bin;
    # this one belongs in libexec, since it takes a secret on stdin and is only
    # meaningful inside a PAM transaction.
    if [ -e "$out/bin/irlume-kwallet-init" ]; then
      install -Dm0755 "$out/bin/irlume-kwallet-init" \
        "$out/libexec/irlume/irlume-kwallet-init"
      rm "$out/bin/irlume-kwallet-init"
    fi

    install -d "$out/share/irlume/models"
    install -m0644 ${models}/*.onnx "$out/share/irlume/models/"

    # The machine-API contract travels with the engine that implements it, so a
    # consumer validating our JSON never has to guess which schema this build
    # speaks.
    install -Dm0644 schemas/machine-api-v1.schema.json \
      "$out/share/irlume/schemas/machine-api-v1.schema.json"
  '';

  meta = {
    description = "Windows Hello-style IR face login for Linux";
    homepage = "https://github.com/archledger/irlume";
    license = lib.licenses.gpl3Only;
    platforms = lib.platforms.linux;
    mainProgram = "irlume";
  };
}

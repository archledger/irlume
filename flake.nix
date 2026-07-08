{
  # irlume development environment, pinned and reproducible with Nix.
  #
  #   nix develop            # drop into a shell with the whole toolchain
  #   cargo build --release  # build everything, no distro packages required
  #
  # Every input below is version-locked by flake.lock, so every contributor
  # and CI get byte-identical tooling regardless of which distro they run.
  # See docs/DEVELOPMENT.md for the walkthrough (and the non-Nix path).
  description = "irlume — reproducible Rust dev environment (face auth for Linux)";

  inputs = {
    # The package set. flake.lock pins it to an exact commit on first use;
    # `nix flake update` bumps it deliberately.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Lets us request an exact Rust toolchain version (irlume's MSRV).
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Generates the outputs for each CPU/OS (x86_64-linux, aarch64-linux, …)
    # so we don't hand-write per-system boilerplate.
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # Pin Rust to irlume's declared MSRV (Cargo.toml `rust-version`).
        # `.default` also brings cargo, rustfmt and clippy. Bump this string
        # in lockstep with Cargo.toml when the floor moves.
        rustToolchain = pkgs.rust-bin.stable."1.88.0".default;

        # irlume needs onnxruntime >= 1.24 (the api-24 ABI). nixpkgs ships an
        # older build, so we pin the exact upstream release the RPM/.deb bundle.
        # `ort` uses load-dynamic, so this is only needed to RUN, not to build.
        ortVersion = "1.24.4";
        onnxruntime-bin = pkgs.stdenv.mkDerivation {
          pname = "onnxruntime-linux-x64";
          version = ortVersion;
          src = pkgs.fetchurl {
            url = "https://github.com/microsoft/onnxruntime/releases/download/v${ortVersion}/onnxruntime-linux-x64-${ortVersion}.tgz";
            hash = "sha256-OiEfvqJSweZikGWPG3NbdyBWFJ8oMh5xwwiULNtUt0c=";
          };
          # A prebuilt binary: unpack it and expose just the shared library.
          # autoPatchelf fixes its library paths so it also runs on NixOS.
          nativeBuildInputs = [ pkgs.autoPatchelfHook ];
          buildInputs = [ pkgs.stdenv.cc.cc.lib ];  # libstdc++ the .so needs
          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib
            cp -a lib/libonnxruntime.so* $out/lib/
            runHook postInstall
          '';
        };
      in {
        devShells.default = pkgs.mkShell {
          # Tools that run at build time (compilers, generators).
          nativeBuildInputs = [
            rustToolchain
            pkgs.pkg-config   # tss-esapi discovers the TPM libs through this
            pkgs.clang        # C toolchain + libclang frontend for bindgen
          ];
          # Libraries the build links against (added to PKG_CONFIG_PATH + linker).
          buildInputs = [
            pkgs.tpm2-tss     # TPM 2.0 stack — the tss-esapi crate links tss2-*
            pkgs.linux-pam    # libpam — the pamsm crate links it
          ];

          # bindgen (pulled in transitively by v4l2-sys-mit) dlopens libclang
          # at build time and has to be told where it lives.
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          # v4l2-sys-mit's bindgen parses <linux/videodev2.h>; hand clang the
          # kernel UAPI headers so it can find it.
          BINDGEN_EXTRA_CLANG_ARGS = "-isystem ${pkgs.linuxHeaders}/include";

          # ort load-dynamic: where libonnxruntime.so lives at runtime.
          ORT_DYLIB_PATH = "${onnxruntime-bin}/lib/libonnxruntime.so";

          shellHook = ''
            echo "▸ irlume dev shell  ($(rustc --version))"
            echo "    build : cargo build --release"
            echo "    lint  : cargo clippy"
            echo "    run   : cargo run -p irlume-cli -- doctor"
            echo "  Note: this shell builds and runs the code, but real face /"
            echo "  camera / TPM / PAM testing still needs a physical machine."
          '';
        };
      });
}

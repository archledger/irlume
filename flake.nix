{
  # irlume development environment, pinned and reproducible with Nix.
  #
  #   nix develop            # drop into a shell with the whole toolchain
  #   cargo build --release  # build everything, no distro packages required
  #
  # Every input below is version-locked by flake.lock, so every contributor
  # and CI get byte-identical tooling regardless of which distro they run.
  # See docs/DEVELOPMENT.md for the walkthrough (and the non-Nix path).
  description = "irlume: reproducible Rust dev environment (face auth for Linux)";

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
    # System-independent outputs (the NixOS module) merged with the per-system
    # ones (dev shell, package) below.
    {
      # nixosModules.irlume: the daemon, camera access, and the empirically
      # derived per-greeter PAM wiring. See nix/module.nix and docs/NIXOS.md.
      nixosModules.irlume = import ./nix/module.nix;
      nixosModules.default = self.nixosModules.irlume;
    }
    // flake-utils.lib.eachDefaultSystem (system:
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
        # `nix build` / `nix run .#irlume`: build irlume from source. The model
        # weights (Git LFS) install into the result; the NixOS module points the
        # daemon at them. `src = self` uses the flake's own tree.
        packages.default = pkgs.callPackage ./nix/package.nix { src = self; };
        packages.irlume = self.packages.${system}.default;
        # Exposed so CI can realize this fixed-output fetch and catch a stale
        # hash; nix/module.nix carries the same URL+hash pair (keep them in
        # step when bumping ortVersion).
        packages.onnxruntime-bin = onnxruntime-bin;

        # `nix flake check` runs these. The module's per-greeter PAM control
        # flags are its whole reason to exist, so instantiate it in a throwaway
        # nixosSystem and assert the decision table. The asserts fire at eval
        # time, so this guards against a regression even under `--no-build`
        # (what CI runs); the derivation itself is trivial to build.
        checks.irlume-module =
          let
            sys = nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [
                ./nix/module.nix
                {
                  # A minimal config so the module system evaluates; none of it
                  # is booted, it only has to type-check.
                  boot.loader.grub.enable = false;
                  fileSystems."/" = {
                    device = "/dev/sda1";
                    fsType = "ext4";
                  };
                  system.stateVersion = "25.11";
                  services.irlume = {
                    enable = true;
                    pam.services = {
                      sddm = { }; # graphical login
                      "gdm-password" = { }; # GNOME login
                      greetd = { }; # text-mode login
                      ly = { }; # text-mode login
                      kde = { }; # lock screen
                      swaylock = { }; # lock screen
                      hyprlock = { }; # lock screen
                    };
                  };
                }
              ];
            };
            pam = sys.config.security.pam.services;
            authCtl = svc: pam.${svc}.rules.auth.irlume.control;
            login = "[success=1 default=ignore]";
          in
          # Login greeters keep the keyring in the stack; lock screens grant
          # outright; text-mode greeters force pam_kwallet to run.
          assert authCtl "sddm" == login;
          assert authCtl "gdm-password" == login;
          assert authCtl "greetd" == login;
          assert authCtl "ly" == login;
          assert pam.greetd.kwallet.forceRun;
          assert pam.ly.kwallet.forceRun;
          assert authCtl "kde" == "sufficient";
          assert authCtl "swaylock" == "sufficient";
          assert authCtl "hyprlock" == "sufficient";
          assert sys.config.systemd.services.irlumed.environment.IRLUME_SOCKET == "/run/irlume.sock";
          pkgs.runCommand "irlume-module-checks-ok" { } "echo 'irlume module PAM decision table verified' > $out";

        devShells.default = pkgs.mkShell {
          # Tools that run at build time (compilers, generators).
          nativeBuildInputs = [
            rustToolchain
            pkgs.pkg-config   # tss-esapi discovers the TPM libs through this
            pkgs.clang        # C toolchain + libclang frontend for bindgen
          ];
          # Libraries the build links against (added to PKG_CONFIG_PATH + linker).
          buildInputs = [
            pkgs.tpm2-tss     # TPM 2.0 stack; the tss-esapi crate links tss2-*
            pkgs.linux-pam    # libpam; the pamsm crate links it
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

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
        ortVersion = "1.28.1";
        onnxruntime-bin = pkgs.stdenv.mkDerivation {
          pname = "onnxruntime-linux-x64";
          version = ortVersion;
          src = pkgs.fetchurl {
            url = "https://github.com/microsoft/onnxruntime/releases/download/v${ortVersion}/onnxruntime-linux-x64-${ortVersion}.tgz";
            hash = "sha256-JSmu+WjQrQYDNlBUvEbr76fw/jvBLyjF9ynJnd/+KoE=";
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
        # weights are fetched by hash inside nix/package.nix (from the models-v1
        # release, not Git LFS) and install into the result; the NixOS module
        # points the daemon at them. `src = self` uses the flake's own tree.
        packages.default = pkgs.callPackage ./nix/package.nix { src = self; };
        packages.irlume = self.packages.${system}.default;
        # Plasma System Settings module (optional; see docs/KCM.md). Not part
        # of packages.default: loading on NixOS needs the nixpkgs#296999
        # caveat verified on a real host first.
        packages.irlume-kcm = pkgs.callPackage ./nix/package-kcm.nix { src = self; };
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
            lib = nixpkgs.lib;
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
            # Current nixpkgs renders SDDM's PAM as a `substack login` line
            # (order 10100) instead of a flat module chain, so the module must
            # place its unseal line before that substack and a pam_permit
            # landing after it. Assert the rendered text on a system that
            # actually enables SDDM; the minimal system above has no DM.
            sysSddm = nixpkgs.lib.nixosSystem {
              inherit system;
              modules = [
                ./nix/module.nix
                {
                  boot.loader.grub.enable = false;
                  fileSystems."/" = {
                    device = "/dev/sda1";
                    fsType = "ext4";
                  };
                  system.stateVersion = "25.11";
                  services.displayManager.sddm.enable = true;
                  # Give the flat `login` chain a keyring rule so the
                  # placement assertions exercise the real anchor shape.
                  security.pam.services.login.kwallet.enable = true;
                  # A real (harmless) policy stack for the integration
                  # fixture below to delegate through.
                  security.pam.services.company-policy.rules.auth = {
                    env = {
                      control = "optional";
                      modulePath = "/lib/security/pam_env.so";
                      order = 10100;
                    };
                    deny = {
                      control = "required";
                      modulePath = "/lib/security/pam_deny.so";
                      order = 10200;
                    };
                  };
                  security.pam.services.irlume-policy-then-login.rules.auth = {
                    company-policy = {
                      control = "include";
                      modulePath = "company-policy";
                      order = 10000;
                    };
                    login = {
                      control = "substack";
                      modulePath = "login";
                      order = 10100;
                    };
                  };
                  services.irlume = {
                    enable = true;
                    pam.services = {
                      sddm = { }; # substack architecture
                      login = { }; # flat tty chain
                      "irlume-policy-then-login" = { };
                    };
                  };
                }
              ];
            };
            lineIndexOf = text: needle:
              let
                # builtins.split interleaves null separators; drop them so
                # indices count rendered lines and adjacency means +1.
                lines = lib.filter builtins.isString (builtins.split "\n" text);
                found = lib.lists.findFirstIndex
                  (l: lib.strings.hasInfix needle l)
                  (-1)
                  lines;
              in found;
            sddmText = sysSddm.config.security.pam.services.sddm.text;
            loginText = sysSddm.config.security.pam.services.login.text;
            policyThenLoginText = sysSddm.config.security.pam.services.irlume-policy-then-login.text;
            # Pure placement unit tests: every rejection returns ok = false
            # instead of throwing, so no tryEval is needed.
            placement = import ./nix/lib.nix { inherit lib; };
            # The accept-shape inner stack mirrors nixpkgs' login chain,
            # whose required pam_deny makes a wrong password fatal.
            defaultInner = sn: [
              (plain "unix-early" "optional" "/lib/security/pam_unix.so" 11700)
              (plain "kwallet" "optional" "/lib/security/pam_kwallet5.so" 12100)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 12900)
              (plain "deny" "required" "/lib/security/pam_deny.so" 13700)
            ];
            r =
              n: o: placement.computePlacement { profile = n; others = o; innerOf = defaultInner; };
            sub = name: order: { inherit name order; control = "substack"; modulePath = name; enable = true; };
            plain = name: control: modulePath: order: { inherit name control modulePath order; enable = true; };
            sddmShape = [ (sub "login" 10100) ];
            policyFirst = [
              (sub "company-policy" 10000)
              (sub "login" 10100)
            ];
            flatShape = [
              (plain "unix-early" "optional" "/lib/security/pam_unix.so" 11700)
              (plain "kwallet" "optional" "/lib/security/pam_kwallet5.so" 12100)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 12900)
              (plain "deny" "required" "/lib/security/pam_deny.so" 13700)
            ];
            ambiguous = [
              (sub "foo-policy" 10000)
              (sub "bar-auth" 10100)
            ];
            jumpBreaker = [
              (plain "gate" "[success=1 default=ignore]" "/lib/security/pam_succeed_if.so" 10000)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            occupied = [
              (plain "rootok" "sufficient" "/lib/security/pam_rootok.so" 10099)
              (sub "login" 10100)
            ];
            tie = [
              (plain "other" "optional" "/lib/security/pam_env.so" 10100)
              (sub "login" 10100)
            ];
            loneUnknownSub = [
              (sub "company-policy" 10100)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            jumpLanding = [
              (plain "gate" "[success=1 default=ignore]" "/lib/security/pam_succeed_if.so" 10000)
              (plain "filler" "optional" "/lib/security/pam_env.so" 10100)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            gatedInner = sn: [
              (plain "nologin" "required" "/lib/security/pam_nologin.so" 10000)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            delegatingInner = sn:
              if sn == "login" then
                [ (plain "via" "include" "common-auth" 11000) ]
              else
                [
                  (plain "nologin" "required" "/lib/security/pam_nologin.so" 10000)
                  (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
                ];
            bracketedGateInner = sn: [
              (plain "allow" "[success=done default=die]" "/lib/security/pam_succeed_if.so" 10000)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
              (plain "deny" "required" "/lib/security/pam_deny.so" 12000)
            ];
            noFatalInner = sn: [
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
              (plain "kwallet" "optional" "/lib/security/pam_kwallet5.so" 12000)
            ];
            jumpSpaced = [
              (plain "gate" "[success = 1 default=ignore]" "/lib/security/pam_succeed_if.so" 10000)
              (plain "filler" "optional" "/lib/security/pam_env.so" 10100)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            jumpOnDefault = [
              (plain "gate" "[success=ok default=1]" "/lib/security/pam_succeed_if.so" 10000)
              (plain "filler" "optional" "/lib/security/pam_env.so" 10100)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            inc = name: order: { inherit name order; control = "include"; modulePath = name; enable = true; };
            includeLogin = [ (inc "login" 10100) ];
            loneUnknownInc = [ (inc "company-policy" 10100) ];
            loneUnknownIncUnix = [
              (inc "company-policy" 10100)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            noAnchor = [
              (plain "env" "optional" "/lib/security/pam_env.so" 10000)
            ];
            jumpEqRight = [
              (plain "gate" "[success =1 default=ignore]" "/lib/security/pam_succeed_if.so" 10000)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            jumpEqLeft = [
              (plain "gate" "[success= 1 default=ignore]" "/lib/security/pam_succeed_if.so" 10000)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
            ];
            subUpper = [
              { name = "login"; order = 10100; control = "Substack"; modulePath = "login"; enable = true; }
            ];
            sawRequiredInner = sn:
              if sn == "login" then
                [
                  (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
                  (plain "deny" "required" "/lib/security/pam_deny.so" 12000)
                  (plain "sess" "include" "common-session" 13000)
                ]
              else
                [ (plain "kwallet" "optional" "/lib/security/pam_kwallet5.so" 10000) ];
            gateCaseInner = sn: [
              (plain "nologin" "Required" "/lib/security/pam_nologin.so" 10000)
              (plain "unix" "sufficient" "/lib/security/pam_unix.so" 11000)
              (plain "deny" "required" "/lib/security/pam_deny.so" 12000)
            ];
            includeJumpPair = [
              (inc "site-policy" 10000)
              (inc "login" 10100)
            ];
            sitePolicyJump = sn:
              if sn == "site-policy" then
                [ (plain "fp" "[success=1 default=ignore]" "/lib/security/pam_fprintd.so" 10000) ]
              else
                defaultInner sn;
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
          # Lock screens never get an enabled landing rule; the sufficient
          # grant needs no jump.
          assert !pam.kde.rules.auth.irlume-landing.enable;
          # SDDM: the unseal line is immediately before the login substack
          # and the pam_permit landing immediately after it, so a face
          # success jumps over exactly that substack (whose pam_unix would
          # fail on the empty Enter that armed the face scan) and lands on
          # the permit. Strict adjacency: no other auth rule may sit in the
          # jump's path.
          assert (lineIndexOf sddmText "pam_irlume.so unseal") != -1;
          assert (lineIndexOf sddmText "pam_irlume.so unseal") + 1 == (lineIndexOf sddmText "substack login");
          assert (lineIndexOf sddmText "substack login") + 1 == (lineIndexOf sddmText "pam_permit.so");
          # A flat login chain gets NO permit landing (the trailing required
          # pam_deny makes an optional success on the failure path a
          # bypass on deny-less stacks, and pamwire adds one only around
          # substacks). The face line sits immediately before the password
          # prompt (unix-early), so a face success skips that prompt and
          # pam_kwallet and the try_first_pass pam_unix still see the
          # released token.
          assert (lineIndexOf loginText "pam_irlume.so unseal") + 1 == (lineIndexOf loginText "pam_unix.so likeauth nullok");
          assert !(lib.strings.hasInfix "pam_permit.so" loginText);
          assert (lineIndexOf loginText "pam_unix.so likeauth nullok") < (lineIndexOf loginText "pam_kwallet5.so");
          # With a policy include ahead of the known password substack, the
          # face line anchors on the password stack (here `login`), and the
          # policy still renders ABOVE the face line, so a face success never
          # skips it.
          assert (lineIndexOf policyThenLoginText "include company-policy") != -1;
          assert (lineIndexOf policyThenLoginText "include company-policy") < (lineIndexOf policyThenLoginText "pam_irlume.so unseal");
          assert (lineIndexOf policyThenLoginText "pam_irlume.so unseal") + 1 == (lineIndexOf policyThenLoginText "substack login");
          assert (lineIndexOf policyThenLoginText "substack login") + 1 == (lineIndexOf policyThenLoginText "pam_permit.so");
          # Placement unit tests: the accepted shapes compute their slots and
          # every unsafe layout is rejected with a reason (ok = false), which
          # the module turns into an evaluation error.
          assert (r "login" sddmShape).ok && (r "login" sddmShape).unsealOrder == 10050 && (r "login" sddmShape).landingEnable && (r "login" sddmShape).landingOrder == 10150;
          assert (r "login" policyFirst).ok && (r "login" policyFirst).unsealOrder == 10099;
          assert (r "login" flatShape).ok && (r "login" flatShape).unsealOrder == 11650 && !(r "login" flatShape).landingEnable;
          assert (r "lock" flatShape).ok && (r "lock" flatShape).unsealOrder == 11000 && !(r "lock" flatShape).landingEnable;
          assert !(r "login" ambiguous).ok;
          assert builtins.isString (r "login" ambiguous).reason;
          assert !(r "login" jumpBreaker).ok;
          assert !(r "login" occupied).ok;
          assert !(r "login" tie).ok;
          assert !(placement.computePlacement { profile = "login"; others = sddmShape; innerOf = gatedInner; }).ok;
          # A lone substack that is not a known password stack is rejected,
          # not anchored on.
          assert !(r "login" loneUnknownSub).ok;
          # Inserting exactly where an existing jump lands also rewrites it.
          assert !(r "login" jumpLanding).ok;
          # A required gate behind a nested include is still found.
          assert !(placement.computePlacement { profile = "login"; others = sddmShape; innerOf = delegatingInner; }).ok;
          # An extended control inside the skipped stack is unproven.
          assert !(placement.computePlacement { profile = "login"; others = sddmShape; innerOf = bracketedGateInner; }).ok;
          # A delegation to an unknown service is unproven, not empty-safe.
          assert !(placement.computePlacement { profile = "login"; others = sddmShape; innerOf = sn: null; }).ok;
          # A stack with no required rule cannot keep a wrong password fatal.
          assert !(placement.computePlacement { profile = "login"; others = sddmShape; innerOf = noFatalInner; }).ok;
          # Numeric jumps in spaced or non-success forms still parse.
          assert !(r "login" jumpSpaced).ok;
          assert !(r "login" jumpOnDefault).ok;
          # A top-level include anchors exactly like a substack, and its
          # stack is inspected for gates.
          assert (r "login" includeLogin).ok && (r "login" includeLogin).unsealOrder == 10050 && (r "login" includeLogin).landingEnable && (r "login" includeLogin).landingOrder == 10150;
          assert !(placement.computePlacement { profile = "login"; others = includeLogin; innerOf = gatedInner; }).ok;
          # A lone include of an unknown stack is refused, with or without a
          # direct pam_unix to fall back on.
          assert !(r "login" loneUnknownInc).ok;
          assert !(r "login" loneUnknownIncUnix).ok;
          # A non-empty chain with no pam_unix and no delegation has no
          # anchor; an empty chain stays inert.
          assert !(r "login" noAnchor).ok;
          assert (r "login" [ ]).ok;
          # One-sided whitespace in a numeric action still parses as a jump.
          assert !(r "login" jumpEqRight).ok;
          assert !(r "login" jumpEqLeft).ok;
          # Control keywords are case-insensitive: Substack delegates, and an
          # uppercase Required gate is still a gate.
          assert (r "login" subUpper).ok && (r "login" subUpper).unsealOrder == 10050;
          assert !(placement.computePlacement { profile = "login"; others = sddmShape; innerOf = gateCaseInner; }).ok;
          # Required evidence survives an optional-only nested include.
          assert (placement.computePlacement { profile = "login"; others = sddmShape; innerOf = sawRequiredInner; }).ok;
          # A jump inside an include expansion refuses the whole wiring.
          assert !(placement.computePlacement { profile = "login"; others = includeJumpPair; innerOf = sitePolicyJump; }).ok;
          assert sys.config.systemd.services.irlumed.environment.IRLUME_SOCKET == "/run/irlume.sock";
          # These shipped PAD cues default to /etc/irlume in the daemon.
          # A NixOS service must resolve them from its selected package too.
          assert (sys.config.systemd.services.irlumed.environment.IRLUME_VIT_PAD_MODEL or null)
            == "${sys.config.services.irlume.package}/share/irlume/models/liveness_vit.onnx";
          assert (sys.config.systemd.services.irlumed.environment.IRLUME_PAD_IR_MODEL or null)
            == "${sys.config.services.irlume.package}/share/irlume/models/flir.onnx";
          pkgs.runCommand "irlume-module-checks-ok" { } "echo 'irlume module PAM decision table verified' > $out";

        # Actual helper/PAM recovery under NixOS, including unsafe-mode refusal.
        # Limit the VM check to the architecture supported by the bundled ORT.
        checks.${if system == "x86_64-linux" then "irlume-retry-recovery" else null} =
          pkgs.testers.runNixOSTest { imports = [ ./nix/tests/retry-recovery.nix ]; };

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
            pkgs.dbus
            pkgs.systemd      # libudev for the camera lifecycle adapter
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

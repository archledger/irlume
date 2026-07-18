## NixOS module for irlume: the daemon, camera access, and the PAM wiring.
##
##   services.irlume = {
##     enable = true;
##     pam.services.sddm = {};   # graphical login  -> face unlocks the wallet
##     pam.services.kde   = {};  # Plasma lock screen -> face unlocks it
##   };
##
## The PAM control flags below are not guesses; each was derived on a live VM
## against the actual greeter/lock stacks (docs/NIXOS.md records the matrix).
## The short version:
##
##   * A login greeter (sddm, gdm-password, greetd, ly, tty login) gets
##     `[success=1 default=ignore]`, NOT `sufficient`. It records the face
##     success but skips exactly one rule, so pam_kwallet / pam_gnome_keyring
##     still runs and unseals the wallet, and pam_unix grants on the token the
##     daemon unsealed. `sufficient` would short-circuit past the keyring and
##     leave the session with a locked wallet.
##
##   * A lock screen (kde, swaylock, hyprlock) gets `sufficient`. The wallet is
##     already open in the live session, so there is no keyring handoff to make;
##     and pam_unix on a verify-only unlock cannot grant, so a `success=1` jump
##     would fall through to pam_deny. `sufficient` grants the unlock outright.
##
##   * A text-mode greeter (greetd, ly) is not seen as a graphical session, so
##     pam_kwallet skips itself unless told otherwise. When such a service opts
##     in, this module sets its kwallet `forceRun = true` so the wallet still
##     unseals from the login token.
##
## The keyring backend itself (KWallet on Plasma, gnome-keyring on GNOME/wlroots)
## is whatever your desktop already enables; this module does not pick one. For
## greetd on a wlroots compositor there is one more piece, the keyring session
## wrapper, documented in docs/NIXOS.md and exposed here as
## `config.services.irlume.keyringSessionWrapper`.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.irlume;

  # Well-known PAM services and the profile each one needs. A name not listed
  # here defaults to "login" (the safe choice for an unrecognised greeter);
  # override per service with `pam.services.<name>.profile`.
  knownLock = [
    "kde"
    "swaylock"
    "hyprlock"
    "gtklock"
    "waylock"
  ];
  # Text-mode greeters: not a graphical session, so kwallet needs forceRun.
  tuiGreeters = [
    "greetd"
    "ly"
  ];

  pamServiceModule =
    { name, ... }:
    {
      options = {
        profile = lib.mkOption {
          type = lib.types.enum [
            "login"
            "lock"
          ];
          default = if lib.elem name knownLock then "lock" else "login";
          description = ''
            Which PAM profile to splice in. "login" (greeters, tty login) uses
            `[success=1 default=ignore]` so the keyring still unseals; "lock"
            (screen lockers) uses `sufficient`. Recognised service names get the
            right default; set this explicitly for anything unusual.
          '';
        };
      };
    };

  # The pinned onnxruntime 1.24.4 build. NixOS stable ships 1.22.2, which is
  # below irlume's 1.24 API floor and deadlocks the `ort` loader at startup, so
  # bundle the exact upstream release the RPM and .deb carry.
  onnxruntime-bin = pkgs.stdenv.mkDerivation {
    pname = "onnxruntime-linux-x64";
    version = "1.24.4";
    src = pkgs.fetchurl {
      url = "https://github.com/microsoft/onnxruntime/releases/download/v1.24.4/onnxruntime-linux-x64-1.24.4.tgz";
      hash = "sha256-OiEfvqJSweZikGWPG3NbdyBWFJ8oMh5xwwiULNtUt0c=";
    };
    nativeBuildInputs = [ pkgs.autoPatchelfHook ];
    buildInputs = [ pkgs.stdenv.cc.cc.lib ];
    installPhase = ''
      runHook preInstall
      mkdir -p $out/lib
      cp -a lib/libonnxruntime.so* $out/lib/
      runHook postInstall
    '';
  };

  models = "${cfg.package}/share/irlume/models";
  pamModule = "${cfg.package}/lib/security/pam_irlume.so";
  pamArgs = [
    "unseal"
    "ondemand"
  ];

  # Turn one opted-in service into a NixOS PAM auth rule.
  mkAuthRule = svc: {
    control = if svc.profile == "lock" then "sufficient" else "[success=1 default=ignore]";
    modulePath = pamModule;
    args = pamArgs;
    order = 11000;
  };

  # greetd on a wlroots compositor does not export the keyring's control socket
  # into the session, so a second, locked daemon spawns and apps prompt. Wrap
  # the compositor command with this: it starts one keyring and pushes its
  # environment into the user's systemd + dbus activation environment.
  #   services.greetd.settings.default_session.command =
  #     "${tuigreet} --cmd '${config.services.irlume.keyringSessionWrapper} Hyprland'";
  keyringSessionWrapper = pkgs.writeShellScript "irlume-keyring-session" ''
    export GNOME_KEYRING_CONTROL="$XDG_RUNTIME_DIR/keyring"
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/keyring/ssh"
    ${pkgs.gnome-keyring}/bin/gnome-keyring-daemon --start --components=secrets,ssh,pkcs11 >/dev/null 2>&1 || true
    ${pkgs.dbus}/bin/dbus-update-activation-environment --systemd GNOME_KEYRING_CONTROL SSH_AUTH_SOCK >/dev/null 2>&1 || true
    exec "$@"
  '';
in
{
  options.services.irlume = {
    enable = lib.mkEnableOption "the irlume IR face-authentication daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The irlume package providing irlumed, the PAM module, and the model weights.";
    };

    rgbDevice = lib.mkOption {
      type = lib.types.str;
      default = "/dev/video0";
      description = "V4L2 node for the RGB camera.";
    };

    irDevice = lib.mkOption {
      type = lib.types.str;
      default = "/dev/video2";
      description = "V4L2 node for the IR camera.";
    };

    sequentialCapture = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Capture the RGB and IR streams one after another instead of
        concurrently. Real hardware sustains both at once; USB passthrough into
        a VM cannot, so set this only when testing irlume inside a VM.
      '';
    };

    pam.services = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule pamServiceModule);
      default = { };
      example = lib.literalExpression ''
        {
          sddm = { };            # graphical login, profile "login"
          kde = { };             # Plasma lock, profile "lock" (auto)
          greetd.profile = "login";
        }
      '';
      description = ''
        PAM services to add irlume face auth to, keyed by the PAM service name
        (the file under /etc/pam.d). Each recognised name gets the correct
        control flag automatically; see this module's header for the rules.
      '';
    };

    keyringSessionWrapper = lib.mkOption {
      type = lib.types.path;
      readOnly = true;
      default = keyringSessionWrapper;
      defaultText = lib.literalExpression "<generated keyring session wrapper>";
      description = ''
        A script that starts one gnome-keyring and exports its environment, for
        wrapping a greetd compositor command so a wlroots session does not spawn
        a second, locked keyring. See docs/NIXOS.md.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    systemd.services.irlumed = {
      description = "irlume face authentication daemon";
      documentation = [ "https://github.com/archledger/irlume" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/irlumed";
        Restart = "on-failure";
        RestartSec = 2;
      };
      environment = {
        ORT_DYLIB_PATH = "${onnxruntime-bin}/lib/libonnxruntime.so";
        IRLUME_DET_MODEL = "${models}/face_detection_yunet_2023mar.onnx";
        IRLUME_MODEL = "${models}/glintr100.onnx";
        IRLUME_MESH_MODEL = "${models}/face_landmark.onnx";
        IRLUME_BLAZE_MODEL = "${models}/blaze_face_short_range.onnx";
        IRLUME_SOCKET = "/run/irlume.sock";
        IRLUME_RGB_DEVICE = cfg.rgbDevice;
        IRLUME_IR_DEVICE = cfg.irDevice;
      } // lib.optionalAttrs cfg.sequentialCapture { IRLUME_SEQUENTIAL_CAPTURE = "1"; };
    };

    # The daemon opens the camera nodes; keep them group-readable for `video`.
    services.udev.extraRules = ''
      KERNEL=="video[0-9]*", SUBSYSTEM=="video4linux", GROUP="video", MODE="0660"
    '';

    # Splice pam_irlume into each opted-in service with its resolved control.
    security.pam.services = lib.mkMerge [
      (lib.mapAttrs (_: svc: { rules.auth.irlume = mkAuthRule svc; }) cfg.pam.services)
      # Text-mode greeters are not a graphical session, so pam_kwallet skips
      # itself unless forced. Only meaningful when the service actually enables
      # kwallet; harmless otherwise.
      (lib.mkMerge (
        map (name: { ${name}.kwallet.forceRun = true; }) (
          lib.filter (n: lib.elem n tuiGreeters) (lib.attrNames cfg.pam.services)
        )
      ))
    ];
  };
}

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
##     leave the session with a locked wallet. A pam_permit landing rule
##     catches the jump on services whose auth nixpkgs renders as a
##     `substack` (SDDM on current nixpkgs); there the face line goes
##     immediately before that substack and the landing immediately after it,
##     so a face success skips the whole substack, whose pam_unix would fail
##     on the empty Enter that armed the face scan. Flat chains get no
##     landing; the face line goes immediately before the password-prompting
##     pam_unix instead. The one login layout that DOES get `sufficient` is
##     an `include` anchor: libpam expands an include inline, so a success=N
##     jump would skip only its first expanded rule; the module IGNOREs on
##     cold login and a face match returns immediately, exactly the form
##     `irlume login enable` writes for include layouts on FHS distros
##     (crates/irlume-cli/src/pamwire/grammar.rs, is_include_auth_layout).
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
            `[success=1 default=ignore]` so the keyring still unseals, or
            `sufficient` when the password chain arrives through an `include`;
            "lock" (screen lockers) uses `sufficient`. Recognised service
            names get the right default; set this explicitly for anything
            unusual.
          '';
        };
      };
    };

  # The pinned onnxruntime build. NixOS stable ships 1.22.2, which is below
  # irlume's 1.24 API floor and deadlocks the `ort` loader at startup, so bundle
  # the exact upstream release the RPM and .deb carry.
  #
  # One binding, interpolated into the label and the URL, the way flake.nix
  # already does it. Written out three times, a bump could change the derivation
  # label while still fetching the old archive, and the parity check in
  # scripts/check-packaging-parity.sh reads the label (#411).
  ortVersion = "1.28.1";
  onnxruntime-bin = pkgs.stdenv.mkDerivation {
    pname = "onnxruntime-linux-x64";
    version = ortVersion;
    src = pkgs.fetchurl {
      url = "https://github.com/microsoft/onnxruntime/releases/download/v${ortVersion}/onnxruntime-linux-x64-${ortVersion}.tgz";
      hash = "sha256-JSmu+WjQrQYDNlBUvEbr76fw/jvBLyjF9ynJnd/+KoE=";
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

  # Turn one opted-in service into its NixOS PAM auth rules.
  #
  # A lock screen stays one `sufficient` line: the wallet is already open and
  # the unlock grants outright. A login greeter needs the jump form, mirroring
  # the block `irlume login enable` writes on FHS distros
  # (crates/irlume-cli/src/pamwire.rs): the face success skips exactly one
  # rule, and that rule must be a harmless one, never something load-bearing.
  #
  # Current nixpkgs renders SDDM's auth as `substack login` rather than a
  # flat module chain. On that architecture the unseal line goes IMMEDIATELY
  # before that substack and a `pam_permit` landing IMMEDIATELY after it: an
  # empty Enter at the greeter runs the face scan first, and a face success
  # jumps over the whole substack (whose pam_unix would fail on that same
  # empty password) and lands on the permit, so the login still grants; the
  # required-by-default substack keeps a failed password attempt fatal, so
  # the permit cannot authenticate a failure. Strict adjacency matters: any
  # rule left in the jump's path would be skipped instead of the substack,
  # bypassing a gate such as pam_nologin, so the order slots are derived from
  # the neighbouring rules and evaluation fails when no adjacent slot is
  # free. On a flat chain the unseal line sits immediately before the
  # password-prompting pam_unix, and NO landing is rendered: the jump skips
  # that prompt, and pam_kwallet plus the try_first_pass pam_unix still see
  # the released token, while an optional permit on the failure path would
  # become a deny-less stack's only success.
  #
  # Reading the service's own rules minus ours cannot recurse: attribute
  # names are strict, but removeAttrs leaves the filtered values lazy.
  # Placement of the PAM rules lives in ./lib.nix as pure functions the
  # flake's irlume-module check unit-tests directly; this module only maps
  # the merged config into that shape and turns a rejection into an
  # evaluation error.
  #
  # Design recap: the face line's success jumps over exactly one rule. On a
  # service whose auth nixpkgs renders as a `substack` (SDDM on current
  # nixpkgs), the face line goes immediately before the PASSWORD substack
  # and a pam_permit landing immediately after it, so the jump skips the
  # whole substack (whose pam_unix would fail on the empty Enter that armed
  # the face scan) while any earlier policy substack still runs above the
  # face line. On a flat chain the face line goes immediately before the
  # password-prompting pam_unix and NO landing is rendered: the jump skips
  # that prompt, the keyring module and the try_first_pass pam_unix still
  # see the released token, and an optional permit on the failure path
  # would be a deny-less stack's only success. Lock screens keep a single
  # sufficient line. Every layout the pure functions cannot prove safe
  # (ambiguous substacks, occupied slots, order ties, a numeric jump the
  # insertion would rewrite, required gates inside the skipped substack) is
  # rejected instead of rendered wrong.
  #
  # Reading the service's own rules minus ours cannot recurse: attribute
  # names are strict, but removeAttrs leaves the filtered values lazy. The
  # landing disables itself through its enable flag rather than mkIf,
  # because a conditional definition whose condition reads the same
  # option's merge would force itself while the module system filters
  # conditional definitions.
  placement = import ./lib.nix { inherit lib; };

  # null for an unknown service: a delegation to it is a broken reference
  # the password path would surface, so the placement treats it as
  # unproven instead of scanning an empty rule list.
  svcRuleList =
    name:
    if builtins.hasAttr name config.security.pam.services then
      lib.map
        (r: {
          name = r.name;
          control = r.control;
          modulePath = r.modulePath;
          order = r.order;
          enable = r.enable;
        })
        (
          lib.attrValues (
            removeAttrs (config.security.pam.services.${name}.rules.auth or { }) [
              "irlume"
              "irlume-landing"
            ]
          )
        )
    else
      null;

  mkAuthRules =
    name: svc:
    let
      result = placement.computePlacement {
        profile = svc.profile;
        others = svcRuleList name;
        innerOf = sn: svcRuleList sn;
      };
      placementOrder = if result.ok then result.unsealOrder else throw result.reason;
      landingOrder = if result.ok then result.landingOrder else throw result.reason;
      # The pure placement decides the control: the jump form for a substack
      # or flat chain (the keyring must still run), `sufficient` for a lock
      # screen and for an include anchor, where libpam would expand the
      # rules inline and the jump form would skip only the first one.
      unsealControl = if result.ok then result.unsealControl else throw result.reason;
    in
    {
      irlume = {
        control = unsealControl;
        modulePath = pamModule;
        args = pamArgs;
        order = placementOrder;
      };
      irlume-landing = {
        enable = result.ok && result.landingEnable;
        control = "optional";
        modulePath = "${config.security.pam.package}/lib/security/pam_permit.so";
        order = landingOrder;
      };
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
      # Pass src explicitly: callPackage would otherwise fill the `src` argument
      # from pkgs (where `src` is a renamed alias) instead of the file default.
      default = pkgs.callPackage ./package.nix { src = lib.cleanSource ../.; };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { src = lib.cleanSource ../.; }";
      description = "The irlume package providing irlumed, the PAM module, and the model weights.";
    };

    kcm = {
      enable = lib.mkEnableOption "the irlume Plasma System Settings module (read-only status and launch actions; requires a Plasma 6 session; see docs/KCM.md)";

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.callPackage ./package-kcm.nix { src = lib.cleanSource ../.; };
        defaultText = lib.literalExpression "pkgs.callPackage ./package-kcm.nix { src = lib.cleanSource ../.; }";
        description = "The irlume-kcm Plasma System Settings module package.";
      };
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
    environment.systemPackages = [ cfg.package ] ++ lib.optional cfg.kcm.enable cfg.kcm.package;
    security.polkit.enable = true;
    # polkit links /share/polkit-1 from environment.systemPackages.

    # Setgid root:video directory for the IR-emitter exclusion locks (#542).
    # The service below mirrors the packaged unit's bounding set (no
    # CAP_CHOWN), so a lock the daemon creates cannot be re-grouped
    # in-process; the group must be inherited at creation. Keep this rule in
    # step with packaging/tmpfiles.d/irlume.conf — the conf shipped inside
    # the package is documentation here; THIS line is the operative one on
    # NixOS (nothing scans $out/lib/tmpfiles.d).
    systemd.tmpfiles.rules = [
      # Private persistent machine state. The mode mask tightens a loose
      # existing directory without widening one whose owner bits are stricter.
      "d /var/lib/irlume ~0700 root root -"
      "d /run/lock/irlume 2751 root video -"
    ];

    # systemd owns the socket, so it exists from sockets.target onward rather
    # than only once irlumed has finished loading models. Greeters authenticate
    # well before that, and a PAM client with nothing to connect to loses the
    # keyring release silently (#244). The service still starts at boot, so the
    # first login does not pay for model loading.
    systemd.sockets.irlumed = {
      description = "irlume face authentication socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/irlume.sock";
        # SO_PEERCRED is the authorization boundary; see the daemon's bind site
        # for why the mode is not a second one.
        SocketMode = "0666";
        Accept = false;
      };
    };

    systemd.services.irlumed = {
      description = "irlume face authentication daemon";
      documentation = [ "https://github.com/archledger/irlume" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "multi-user.target" ];
      # /nix/store is normally group-writable (1775), even when mounted read-only.
      # Recovery deliberately rejects writable ancestry. Stage the selected
      # helper in a private, root-owned runtime directory instead of relaxing
      # that trust check. A service restart replaces it with this generation's
      # helper; RuntimeDirectory removes it when the service stops.
      preStart = ''
        if [ -e ${cfg.package}/libexec/irlume-password-verify ]; then
          ${pkgs.coreutils}/bin/install -m0755 ${cfg.package}/libexec/irlume-password-verify /run/irlume-recovery/irlume-password-verify
        else
          # Older or custom package overrides may omit optional recovery.
          # Never reuse a verifier left by a different selected package.
          ${pkgs.coreutils}/bin/rm -f /run/irlume-recovery/irlume-password-verify
          echo "irlumed: selected package has no password verifier; self-service recovery unavailable" >&2
        fi
      '';
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/irlumed";
        Restart = "on-failure";
        RestartSec = 2;
        # Cap the stop wait so a rebuild-switch restart cannot stall (the socket
        # loop exits promptly on SIGTERM; captures open and drop the device per
        # request, so no long-held camera handle).
        TimeoutStopSec = "10s";
        # Wedged-capture watchdog, matching packaging/systemd/irlumed.service.
        # The daemon pings only while its camera worker reports progress, so a
        # capture stuck inside a driver call ends as a bounded restart rather
        # than an indefinite hang. NotifyAccess is required for Type=simple.
        WatchdogSec = "90s";
        NotifyAccess = "main";
        # No core dumps, matching packaging/systemd/irlumed.service: a crash or
        # the watchdog's SIGABRT leaves no core file with its memory. The daemon
        # also sets this limit and clears its dumpable flag at startup.
        LimitCORE = 0;
        # Sandboxing, mirroring packaging/systemd/irlumed.service so the hardening
        # holds on NixOS too. Scoped to what the daemon needs: it opens
        # /dev/video* and the TPM, binds a Unix socket, and writes root-owned
        # state at mode 0600. ProtectHome / PrivateDevices / MemoryDenyWriteExecute
        # are deliberately NOT set (it reads users' homes to tell which keyring an
        # account keeps before a keyring arm, camera + TPM access, and the ONNX
        # runtime JITs).
        NoNewPrivileges = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
        ];
        IPAddressDeny = "any";
        ProtectSystem = "full";
        # The daemon writes the camera pin and the stored capture mode under
        # /etc/irlume, which ProtectSystem=full would otherwise mount read-only.
        # ConfigurationDirectory creates the directory before the namespace is
        # assembled and binds it read-write; the ReadWritePaths entry that used
        # to be here did not, because its leading "-" makes systemd skip a path
        # that does not exist and no lane creates this one (#307). Kept in sync
        # by hand with packaging/systemd/irlumed.service, which nothing in CI
        # enforces.
        ConfigurationDirectory = "irlume";
        RuntimeDirectory = "irlume-recovery";
        RuntimeDirectoryMode = "0700";
        PrivateTmp = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        # CAP_CHOWN is deliberately absent: nothing chowns. See the longer note in
        # packaging/systemd/irlumed.service, including why this list must not be
        # emptied (for a uid-0 service that would grant the full root set).
        CapabilityBoundingSet = [
          "CAP_DAC_OVERRIDE"
          "CAP_FOWNER"
        ];
        UMask = "0027";
      };
      environment = {
        ORT_DYLIB_PATH = "${onnxruntime-bin}/lib/libonnxruntime.so";
        IRLUME_DET_MODEL = "${models}/face_detection_yunet_2023mar.onnx";
        IRLUME_MODEL = "${models}/glintr100.onnx";
        # Nix does not yet package libtensorflowlite_c.so (docs/NIXOS.md), so
        # this lane keeps the pinned ONNX conversion as its production mesh
        # until the runtime dependency is wired. The mesh remains dense-landmark
        # infrastructure for BlazeFace rescue alignment; every FHS lane runs the
        # native default.
        IRLUME_MESH_MODEL = "${models}/face_landmark.onnx";
        IRLUME_BLAZE_MODEL = "${models}/blaze_face_short_range.onnx";
        # PAD cues are shipped in the package, not the daemon's /etc defaults.
        IRLUME_VIT_PAD_MODEL = "${models}/liveness_vit.onnx";
        IRLUME_PAD_IR_MODEL = "${models}/flir.onnx";
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
    # The same ancestry check applies to the dedicated PAM service. Copy this
    # root-owned file rather than resolving an /etc symlink through /nix/store.
    environment.etc."pam.d/irlume-retry-reset".mode = "0644";
    security.pam.services = lib.mkMerge [
      # A dedicated fixed local-password stack; defaults must not add biometrics.
      {
        irlume-retry-reset.text = lib.mkForce (builtins.readFile ../packaging/pam/irlume-retry-reset);
      }
      (lib.mapAttrs (name: svc: { rules.auth = mkAuthRules name svc; }) cfg.pam.services)
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

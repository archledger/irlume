# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
{
  name = "irlume-nixos-retry-recovery";
  globalTimeout = 600;
  nodes.machine = { config, lib, pkgs, ... }: let
    fullPackage = pkgs.callPackage ../package.nix { src = lib.cleanSource ../..; };
    withoutHelper = pkgs.runCommand "irlume-without-password-verifier" { } ''
      mkdir -p $out/libexec
      ln -s ${fullPackage}/bin $out/bin
      ln -s ${fullPackage}/lib $out/lib
      ln -s ${fullPackage}/share $out/share
      ln -s ${fullPackage}/libexec/irlume $out/libexec/irlume
    '';
  in {
    imports = [ ../module.nix ];
    system.stateVersion = "26.05";
    virtualisation = {
      cores = 2;
      memorySize = 4096;
      useNixStoreImage = true;
      mountHostNixStore = false;
      writableStore = true;
    };
    services.irlume.enable = true;
    services.irlume.package = lib.mkDefault fullPackage;
    specialisation.without-helper.configuration = {
      services.irlume.package = lib.mkForce withoutHelper;
      # Simulate a verifier retained from a previously selected package.
      systemd.services.irlumed.preStart = lib.mkBefore ''
        ${pkgs.coreutils}/bin/install -m0755 ${fullPackage}/libexec/irlume-password-verify /run/irlume-recovery/irlume-password-verify
      '';
    };
    users.users.irlume-recovery-test = { isNormalUser = true; uid = 1001; };
    environment.systemPackages = [ pkgs.python3 pkgs.shadow ];
    environment.etc.irlume-recovery-test-marker.text = "disposable-nixos-recovery-test";
    environment.etc.irlume-recovery-test-package.text = toString config.services.irlume.package;
    environment.etc.irlume-recovery-test.source = ./retry-recovery.py;
  };
  testScript = { nodes, ... }: let
    normal = nodes.machine.system.build.toplevel;
    missing = nodes.machine.specialisation.without-helper.configuration.system.build.toplevel;
  in ''
    machine.start()
    machine.wait_for_unit("irlumed.service", timeout=120)
    machine.wait_for_unit("irlumed.socket")
    machine.succeed("systemctl start register-nix-paths.service")
    machine.succeed("python3 /etc/irlume-recovery-test")
    machine.succeed("${missing}/bin/switch-to-configuration test")
    machine.wait_for_unit("irlumed.service", timeout=120)
    machine.succeed("python3 /etc/irlume-recovery-test missing")
    machine.succeed("${normal}/bin/switch-to-configuration test")
    machine.wait_for_unit("irlumed.service", timeout=120)
    machine.succeed("python3 /etc/irlume-recovery-test restored")
    machine.shutdown()
  '';
}

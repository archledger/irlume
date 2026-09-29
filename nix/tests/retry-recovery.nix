# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
{
  name = "irlume-nixos-retry-recovery";
  globalTimeout = 600;
  nodes.machine = { config, pkgs, ... }: {
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
    users.users.irlume-recovery-test = { isNormalUser = true; uid = 1001; };
    environment.systemPackages = [ pkgs.python3 pkgs.shadow ];
    environment.etc.irlume-recovery-test-marker.text = "disposable-nixos-recovery-test";
    environment.etc.irlume-recovery-test-package.text = toString config.services.irlume.package;
    environment.etc.irlume-recovery-test.source = ./retry-recovery.py;
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("irlumed.service")
    machine.wait_for_unit("irlumed.socket")
    machine.succeed("systemctl start register-nix-paths.service")
    machine.succeed("python3 /etc/irlume-recovery-test")
    machine.shutdown()
  '';
}

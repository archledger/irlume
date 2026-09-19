# The Plasma System Settings module (kcm_irlume), built from the same source
# tree as the daemon against nixpkgs' KDE Frameworks 6 (kdePackages).
#
# Produces $out/lib/plugins/plasma/kcms/systemsettings/kcm_irlume.so (the QML
# is bundled inside the plugin) and $out/share/applications/kcm_irlume.desktop.
# The NixOS module (nix/module.nix) adds it via services.irlume.kcm.enable;
# on a non-NixOS Plasma system the desktop file alone is not what discovers
# it, so prefer enabling it through the module there too.
#
# NOTE (nixpkgs#296999): KCM plugins built outside the plasma-desktop package
# set have historically had environment issues loading on NixOS. Verify the
# module actually renders in System Settings on a NixOS host before
# advertising it; the package is not added to the default output for that
# reason.
{
  lib,
  stdenv,
  cmake,
  kdePackages,
  src,
}:

stdenv.mkDerivation {
  pname = "irlume-kcm";
  # Derived from Cargo.toml so it never lags the released version, matching
  # nix/package.nix.
  version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version;
  inherit src;

  # The source tree unpacks flat (see nix/package.nix), so the module's
  # CMakeLists.txt lives at kcm/. The cmake setup hook configures cmakeDir.
  # The cmake hook resolves cmakeDir relative to its build directory, so
  # point at the module's CMakeLists.txt one level up from the build dir.
  cmakeDir = "../kcm";
  # A plugin loaded by systemsettings, not an executable: no wrapper script
  # to generate (systemsettings provides the Qt runtime environment).
  dontWrapQtApps = true;

  nativeBuildInputs = [
    cmake
    kdePackages.extra-cmake-modules
  ];

  buildInputs = [
    kdePackages.kcmutils
    kdePackages.kio
    kdePackages.kirigami
    kdePackages.qtbase
    kdePackages.qtdeclarative
  ];

  # The sandbox has no daemon socket and no irlume CLI; the module's QML
  # and the plugin binary are what this derivation must produce.
  doCheck = false;

  postInstall = ''
    test -f "$out/lib/plugins/plasma/kcms/systemsettings/kcm_irlume.so" ||
      test -f "$out/lib/qt-6/plugins/plasma/kcms/systemsettings/kcm_irlume.so" ||
      { echo "kcm_irlume.so missing from the installed tree"; exit 1; }
    test -f "$out/share/applications/kcm_irlume.desktop" ||
      { echo "kcm_irlume.desktop missing from the installed tree"; exit 1; }
  '';

  meta = {
    description = "Plasma System Settings module for irlume";
    license = lib.licenses.gpl3Plus;
    platforms = lib.platforms.linux;
  };
}

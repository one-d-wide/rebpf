# Test provided binaries in a VM with different kernel versions. The VM uses
# pre-built binaries on the host fs instead of rebuilding them inside the VM.
#
# We currently use NixOS testing infrastructure to build and run the VM image.
# The image already contains many devtools needed for debugging, if not, add
# them to the systemPackages below. See the docs:
# https://nixos.org/manual/nixos/stable/#chap-developing-the-test-driver

{
  pkgs ? import <nixpkgs> { },
  lib ? pkgs.lib,
  bins,
  bin_dir,
}:
let
  dir = "${builtins.toString ./../.}/${builtins.toString bin_dir}";

  kernels = [
    pkgs.linuxPackages_latest
    pkgs.linuxPackages_7_0
    pkgs.linuxPackages_6_18
  ];

  name_for = kernelPackages: "linux-${lib.replaceString "." "_" kernelPackages.kernel.version}";
  machine_for =
    kernelPackages:
    { pkgs, ... }:
    {
      boot.kernelPackages = kernelPackages;

      virtualisation.sharedDirectories.src = {
        target = "/bin_dir";
        source = dir;
      };

      environment.variables.TESTING = 1;
      environment.systemPackages = with pkgs; [ ];
    };
in
pkgs.testers.runNixOSTest {
  name = "test-vm";

  nodes = lib.listToAttrs (map (x: lib.nameValuePair (name_for x) (machine_for x)) kernels);

  testScript =
    { ... }:
    # python
    ''
      import os

      t.assertTrue(os.path.exists("${dir}"))

      targets = "${bins}".split()
      t.assertTrue(len(targets) != 0)

      for m in machines:
          m.start()

          m.wait_for_unit("default.target")
          t.assertIn("Linux", m.succeed("uname"), "Wrong OS")

          for target in targets:
              print(m.succeed(f"/bin_dir/{target}", timeout=30))

          m.shutdown()
    '';

  # skipTypeCheck = true;
  # skipLint = true;

  sshBackdoor = {
    enable = true;
    vsockOffset = 45450; # xkcd.com/221
  };
}

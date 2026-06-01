{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.services.rebpf;
  cfg-gui = config.programs.rebpf-gui;
in
{
  options = {
    services.rebpf = {
      enable = lib.mkEnableOption "Rebpf daemon";
      package = lib.mkPackageOption {
        rebpf = import ./rebpf/default.nix { inherit pkgs; };
      } "rebpf" { };
    };

    programs.rebpf-gui = {
      enable = lib.mkEnableOption "Rebpf-gui";
      package = lib.mkPackageOption {
        rebpf-gui = import ./rebpf-gui/default.nix { inherit pkgs; };
      } "rebpf-gui" { };
    };
  };

  config = {
    environment.systemPackages =
      lib.optional cfg.enable cfg.package ++ lib.optional cfg-gui.enable cfg-gui.package;

    services.dbus.packages = lib.optional cfg.enable cfg.package; # dbus policy

    systemd.services = lib.mkIf cfg.enable {
      rebpf = {
        after = [ "network.target" ];
        wantedBy = [ "network.target" ];
        serviceConfig = {
          BusName = "service.rebpf";
          ExecStart = "${lib.getExe cfg.package}";
        };
      };
    };
  };
}

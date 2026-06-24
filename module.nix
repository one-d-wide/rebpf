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
      user = lib.mkOption {
        type = lib.types.str;
        default = "rebpf";
        # Username is hard-coded in ./contrib/service.rebpf.conf and ./contrib/service.rebpf.policy
        readOnly = true;
      };
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

    # D-Bus policies don't work with systemd's DynamicUser=true
    users.groups.${cfg.user} = { };
    users.users.${cfg.user} = {
      group = cfg.user;
      isSystemUser = true;
    };

    systemd.services = lib.mkIf cfg.enable {
      rebpf = {
        after = [ "network.target" ];
        wantedBy = [ "network.target" ];
        serviceConfig = {
          BusName = "service.rebpf";
          StateDirectory = "rebpf";
          ExecStart = "${lib.getExe cfg.package} --dbus-user ${lib.escapeShellArg cfg.user}";
        };
      };
    };
  };
}

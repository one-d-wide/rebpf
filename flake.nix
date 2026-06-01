{
  inputs.nixpkgs.url = "nixpkgs";

  outputs =
    { nixpkgs, ... }:
    {
      packages = nixpkgs.lib.mapAttrs (system: pkgs: {
        rebpf = import ./rebpf/default.nix { inherit pkgs; };
        rebpf-gui = import ./rebpf-gui/default.nix { inherit pkgs; };
      }) nixpkgs.legacyPackages;

      nixosModules.rebpf = import ./module.nix;
    };
}

{
  pkgs ? import <nixpkgs> { },
  rebpf ? import ./rebpf/default.nix { inherit pkgs; },
}:

let
  runtimeLibs = with pkgs; [
    libbpf
    libcap

    libxkbcommon
    vulkan-loader
    libGL
    wayland

    libx11
    libxcursor
    libxi
  ];
in
pkgs.mkShell {
  buildInputs = rebpf.buildInputs ++ [ pkgs.cargo ];
  inherit (rebpf) VMLINUX BPF_CLANG;

  nativeBuildInputs =
    rebpf.nativeBuildInputs
    ++ (with pkgs; [
      clang-tools
      rust-analyzer
      crate2nix
      mold
    ]);

  RUSTFLAGS = "-C linker=clang -C link-arg=-fuse-ld=mold -C link-arg=-Wl,-rpath,${pkgs.lib.makeLibraryPath runtimeLibs}";
}

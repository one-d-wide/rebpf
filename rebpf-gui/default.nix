#!/usr/bin/env nix-build
{
  pkgs ? import <nixpkgs> { },
}:

let
  # Generated using `crate2nix generate`
  project = pkgs.callPackage ../Cargo.nix { };

  runtimeLibs = with pkgs; [
    libxkbcommon
    vulkan-loader
    wayland
    libGL

    libx11
    libxcursor
    libxi
  ];
in
project.workspaceMembers.rebpf-gui.build.overrideAttrs (prev: {
  installPhase = ''
    ${prev.installPhase or ""}

    patchelf --shrink-rpath $out/bin/rebpf-gui
    patchelf --add-rpath ${pkgs.lib.makeLibraryPath runtimeLibs} $out/bin/rebpf-gui

    mkdir -p $out/share/applications/
    cp ${../contrib/rebpf-gui.desktop} $out/share/applications/rebpf-gui.desktop

    mkdir -p $out/share/icons/hicolor/scalable/apps
    cp ${./icons/rebpf-on-white.svg} $out/share/icons/hicolor/scalable/apps/rebpf-gui.svg
  '';

  dontPatchELF = true;
})

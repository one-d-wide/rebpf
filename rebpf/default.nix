#!/usr/bin/env nix-build
{
  pkgs ? import <nixpkgs> { },
}:

let
  # Generated using `crate2nix generate`
  project = pkgs.callPackage ../Cargo.nix { };
in
project.workspaceMembers.rebpf.build.overrideAttrs (prev: {
  nativeBuildInputs =
    prev.nativeBuildInputs
    ++ (with pkgs; [
      # Tools
      pkg-config
      bpftools
      clang
      rust-bindgen
      rustfmt
    ]);

  buildInputs =
    prev.buildInputs
    ++ (with pkgs; [
      # Dependencies
      libbpf
      libcap.dev
    ]);

  VMLINUX = "${pkgs.linux_latest.dev}/vmlinux";
  BPF_CLANG = "${pkgs.libclang}/bin/clang";

  installPhase = ''
    ${prev.installPhase or ""}

    mkdir -p $out/etc/dbus-1/system.d
    cp ${../contrib/service.rebpf.conf} $out/etc/dbus-1/system.d/service.rebpf.conf

    mkdir -p $out/share/polkit-1/actions
    cp ${../contrib/service.rebpf.policy} $out/share/polkit-1/actions/service.rebpf.policy
  '';
})

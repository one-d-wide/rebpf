#!/usr/bin/env bash
set -euo pipefail

cargo update

crate2nix generate

nix flake update --override-input nixpkgs nixpkgs
./scripts/fake-nixpkgs.sh

#!/bin/sh
set -euo pipefail

fake_path='/nix/store/fake/path

You should explicitly provide a version of nixpkgs for this project to use.

From CLI:

  nix shell --override-input nixpkgs nixpkgs [...]
  nix develop --override-input nixpkgs nixpkgs [...]

From flake.nix:

  this_project = {
    url = "...";
    inputs.nixpkgs.follows = "nixpkgs";
  };

'

flake_path=./flake.lock
supported_lock_ver=7
jq='.nodes.nixpkgs.locked = {
  "lastModified": 0,
  "narHash": "sha256-0000000000000000000000000000000000000000000=",
  "path": '"$(printf "%s" "$fake_path" | jq -R --slurp)"',
  "type": "path"
}'

lock_ver="$(jq -r -- ".version" "$flake_path")"
test -z "$lock_ver" && exit 1

if [[ "$lock_ver" != "$supported_lock_ver" ]]; then
  echo "Flake lock version is not supported: $lock_ver" >/dev/stderr
  echo "Last supported is $supported_lock_ver" >/dev/stderr
  exit 1
fi

lock="$(jq -- "$jq" "$flake_path")"
test -z "$lock" && exit 1

printf "%s" "$lock" >"$flake_path"

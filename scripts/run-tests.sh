#!/usr/bin/env bash

# Currently, we only check if bpf the kernel accepts bpf program.
#
# Actually testing connectivity would require setting up a network interface
# that doesn't take into account destination mac address on packets it receives
# (because we set them to zero if not omitted entirely). The way we have to do
# redirection is quit crude, bypassing iproute subsystem, which means we can't
# rely on the kernel to do ARP discovery finding MAC addresses of neighboring
# interfaces.

set -euo pipefail

run() {
  echo >&2
  echo ">" "$@" >&2
  command "$@"
}

source ./rebpf/build-loader.sh

res="$(
  run nix build \
    --print-out-paths --no-link \
    -f ./scripts/vm-tests.nix \
    --argstr bins "bpf-load" \
    --argstr bin_dir "build/" \
    driver
)"

# To debug inside the vm run `$vm_runner --interactive`, type
# `machine.start()`, wait until it boots, and ssh root@vsock/4545{0,1,2,...}
run "$res/bin/nixos-test-driver" # [--interactive]

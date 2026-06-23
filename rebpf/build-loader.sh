#!/usr/bin/env bash

# Compile the bpf-load.c, a binary calling bpf_init(), and compile_commands.json.
#
# In short, this script does:
#
# - bpftool $VMLINUX -> vmlinux.h
# - $BPF_CLANG bpf.c -> bpf.o
# - bpftool bpf.o -> bpf.skel.c
# - clang bpf-load.c (includes bpf.skel.c) -> bpf-load.o
# - clang bpf-load.o main.c -> bpf-load
# - concatenate compile_commands.json

set -euo pipefail

CLANG="${CLANG:-clang}"
BPF_CLANG="${BPF_CLANG:-clang}"
VMLINUX="${VMLINUX:-/sys/kernel/btf/vmlinux}"
OUT_DIR="${OUT_DIR:-./build}"
REBPF_SRC="${REBPF_SRC:-./rebpf}"

BPF_CFLAGS="-Wall -target bpf -g -O2 $(pkg-config --cflags libbpf) ${BPF_TRACE:+-DBPF_TRACE} ${BPF_TRACE_TIME:+-DBPF_TRACE_TIME}"
CFLAGS="-Wall -O2 $(pkg-config --cflags libbpf libcap) ${BPF_TRACE:+-DBPF_TRACE} ${BPF_TRACE_TIME:+-DBPF_TRACE_TIME}"
LIBS="$(pkg-config --libs libbpf libcap)"

if [[ "${BASH_SOURCE[0]}" -nt "$OUT_DIR" ]]; then
  rm -rf "$OUT_DIR"
fi

mkdir -p "$OUT_DIR"

if [[ ! -e "$OUT_DIR"/vmlinux.h ]]; then
  bpftool btf dump file "$VMLINUX" format c >"$OUT_DIR"/vmlinux.h
fi

if [[ ! -e "$OUT_DIR"/bpf.flags ]] || [[ "$BPF_CFLAGS$CFLAGS" != "$(cat "$OUT_DIR"/bpf.flags)" ]]; then
  echo "$BPF_CFLAGS$CFLAGS" >"$OUT_DIR"/bpf.flags
  rm -f "$OUT_DIR"/bpf.o
fi

for src in $REBPF_SRC/bpf*.{h,c}; do
  [[ "$src" = "$REBPF_SRC/bpf-load.c" ]] && continue
  if [[ ! -e "$OUT_DIR"/bpf.o ]] || [[ "$src" -nt "$OUT_DIR"/bpf.o ]]; then
    "$BPF_CLANG" -MJ "$OUT_DIR"/compile_commands.json.bpf.c $BPF_CFLAGS -I"$OUT_DIR" -c "$REBPF_SRC"/bpf.c -o "$OUT_DIR"/bpf.o
    break
  fi
done

if [[ "$OUT_DIR"/bpf.o -nt "$OUT_DIR"/bpf.skel.c ]]; then
  bpftool gen skeleton "$OUT_DIR"/bpf.o >"$OUT_DIR"/bpf.skel.c
fi

for src in $REBPF_SRC/*.{h,c}; do
  if [[ "$src" -nt "$OUT_DIR"/bpf-load.o ]]; then
    "$CLANG" -MJ "$OUT_DIR"/compile_commands.json.new.bpf-load.c $CFLAGS -I"$OUT_DIR" "$REBPF_SRC"/bpf-load.c -c -o "$OUT_DIR"/bpf-load.o

    echo "void bpf_init(); int main() { bpf_init(); }" >"$OUT_DIR"/main.c
    "$CLANG" $LIBS "$OUT_DIR"/bpf-load.o "$OUT_DIR"/main.c -o "$OUT_DIR"/bpf-load
    echo "Built $OUT_DIR/bpf-load"

    echo "void pause(); void bpf_init(); int main() { bpf_init(); while (1) pause(); }" >"$OUT_DIR"/main-sleep.c
    "$CLANG" $LIBS "$OUT_DIR"/bpf-load.o "$OUT_DIR"/main-sleep.c -o "$OUT_DIR"/bpf-load-sleep
    echo "Built $OUT_DIR/bpf-load-sleep"

    break
  fi
done

if [[ -z "${NO_COMPILE_COMMANDS:-}" ]]; then
  {
    echo "["
    cat "$OUT_DIR"/compile_commands.json.*
    echo "]"
  } >./compile_commands.json
fi

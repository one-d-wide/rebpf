#ifndef BPF_ARENA_C
#define BPF_ARENA_C

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf-shared.h"

#define NUMA_NO_NODE (-1)
#define __arena __attribute__((address_space(1)))

struct {
  __uint(type, BPF_MAP_TYPE_ARENA);
  __uint(map_flags, BPF_F_MMAPABLE);
  __uint(max_entries, ARENA_SIZE / PAGE_SIZE);
} arena SEC(".maps");

u8 __arena *BASE;
u32 BASE_PAGES;

static u8 __arena *get_arena() {
  if (!BASE) {
    if (!BASE_PAGES) {
      BASE_PAGES = 1;
    }
    BASE = bpf_arena_alloc_pages(&arena, NULL, BASE_PAGES, NUMA_NO_NODE, 0);
  }
  return BASE;
}

#endif

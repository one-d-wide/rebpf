#ifndef BPF_DFA_C
#define BPF_DFA_C

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf-arena.c"
#include "bpf-shared.h"
#include "bpf-utils.c"

#define DEAD 0

#define NAME_MAX 255  /* # chars in a file name */
#define PATH_MAX 4096 /* # chars in a path name including nul */

static bool match_regex_rev(const u8 *input, u32 len, DFA *dfa);
static bool match_regex_rev_fin(DFA *dfa);
static bool match_regex_rev_path(const struct file *file, DFA *dfa);

static bool match_regex_rev_path(const struct file *file, DFA *dfa) {
  trace_time_fn();

  const struct dentry *dent = file->f_path.dentry;

  bpf_printk("match_regex_rev_path basename=%s", dent->d_name.name);

  int i;
  bpf_for(i, 0, PATH_MAX) {
    const u8 *name = dent->d_name.name;
    u32 len = dent->d_name.len;

    if (len == 1 && *name == '/') {
      break;
    }

    if (!match_regex_rev(name, len, dfa)) {
      return false;
    }

    if (!match_regex_rev((const u8 *)"/", 1, dfa)) {
      return false;
    }

    const struct dentry *par = dent->d_parent;
    if (par == NULL || dent == par) {
      break;
    }

    dent = par;
  }

  return match_regex_rev_fin(dfa);
}

static bool match_regex_rev(const u8 *input, u32 len, DFA *dfa) {
  u8 __arena *table = get_arena() + dfa->dfa_off;
  u32 __arena *states = (u32 __arena *)(table + 256);

  bpf_printk("Matching dfa_off=%u input: %s", dfa->dfa_off, input);

  u32 this = dfa->start;

  if (len > NAME_MAX + 1) {
    return false;
  }

  for (int i = len - 1; i >= 0; --i) {
    if (this == DEAD) {
      break;
    }

    bpf_printk("state %u, char '%c' (ec %u) => %u", this, input[i],
               table[input[i]], states[this + table[input[i]]]);

    this = states[this + table[input[i]]];
  }

  dfa->start = this;

  if (this == DEAD) {
    bpf_printk("Reached dead state");
    return false;
  }

  return this != DEAD;
}

static bool match_regex_rev_fin(DFA *dfa) {
  u8 __arena *table = get_arena() + dfa->dfa_off;
  u32 __arena *states = (u32 __arena *)(table + 256);

  u32 this = dfa->start;

  if (this == DEAD) {
    bpf_printk("Reached dead state");
    return false;
  }

  this = states[this + dfa->eoi];
  dfa->start = this;

  bpf_printk("Reached EOI on %i %s", this,
             dfa->fin_min <= this && this <= dfa->fin_max ? " (matched)" : "");

  return dfa->fin_min <= this && this <= dfa->fin_max;
}

// Note:
//
// It looks like running a regex is (at least) 10 times slower than plain
// copying memory between dynptrs, based on timings I got from trace_time_fn()
// with BPF_TRACE_TIME=1. On a 10KB packet, it's about ~50000ns vs. ~5000ns.
//
// Partially unrolling loops like commented out below doesn't seem to help.
//
// The mem-copy code used in comparison:
//
//     static u8 BUF[65536];
//     struct bpf_dynptr ptr_buf = {};
//     struct bpf_dynptr ptr_skb = {};
//     bpf_dynptr_from_mem(&BUF[0], 65536, 0, &ptr_buf);
//     bpf_dynptr_from_skb(skb, 0, &ptr_skb);
//     bpf_dynptr_copy(&ptr_buf, 0, &ptr_skb, dns_off, dns_len);
//     parse_dns_from_buf(&BUF[0], dns_len);
//
[[maybe_unused]]
static bool match_regex_fwd(const u8 *input, const u8 *input_end,
                            const DFA *dfa) {
  u8 __arena *table = get_arena() + dfa->dfa_off;
  u32 __arena *states = (u32 __arena *)(table + 256);

  trace_time_fn();

  bpf_printk("Matching dfa_off=%u input: %s", dfa->dfa_off, input);

  u32 this = dfa->start;

  // states[1] = 2;
  // states[2] = 1;
  // this = 1;

  u32 i = 0;

  // #define N 8
  //   // for (; i < 65535; i += N) {
  //   for (; i < 16384; i += N) {
  //     if (input + i + N > input_end) {
  //       break;
  //     }
  //
  // #pragma unroll
  //     for (u32 j = 0; j < N; ++j) {
  //       bpf_printk("batch i=%u, j=%u", i, j);
  //       bpf_printk("state %u, char '%c' (ec %u) => %u", this, input[i + j],
  //                  table[input[i + j]], states[this + table[input[i + j]]]);
  //       this = states[this + table[input[i + j]]];
  //     }
  //   }

  bpf_for(i, i, 65536) {
    if (input + i >= input_end || this == DEAD) {
      break;
    }

    bpf_printk("state %u, char '%c' (ec %u) => %u", this, input[i],
               table[input[i]], states[this + table[input[i]]]);

    this = states[this + table[input[i]]];
  }

  if (this == DEAD) {
    bpf_printk("Reached dead state");
    return false;
  }

  this = states[this + dfa->eoi];

  bpf_printk("Reached EOI on %i %s", this,
             dfa->fin_min <= this && this <= dfa->fin_max ? " (matched)" : "");

  return dfa->fin_min <= this && this <= dfa->fin_max;
}

#endif

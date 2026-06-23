#ifndef BPF_UTILS_C
#define BPF_UTILS_C

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf-shared.h"

[[maybe_unused]]
static u32 ipv4(int a, int b, int c, int d) {
  const u8 rep_u8[4] = {a, b, c, d};
  const u32 rep_u32 = *(u32 *)rep_u8;
  return rep_u32;
}

[[maybe_unused]]
static void print_mac(const char *dir, u8 *b) {
  bpf_printk("%s %02x:%02x:%02x:%02x:%02x:%02x", dir, b[0], b[1], b[2], b[3],
             b[4], b[5]);
}

[[maybe_unused]]
static void print_ipv4(const char *dir, __be32 addr) {
  u8 *b = (void *)&addr;
  bpf_printk("%s %d.%d.%d.%d", dir, b[0], b[1], b[2], b[3]);
}

[[maybe_unused]]
static void print_ipv42(const char *dir, const char *msg, __be32 addr) {
  u8 *b = (void *)&addr;
  bpf_printk("%s %s %d.%d.%d.%d", dir, msg, b[0], b[1], b[2], b[3]);
}

[[maybe_unused]]
static void dump_sock(struct __sk_buff *skb, const char *dir) {
  struct iphdr ipv4;
  int in_off = skb->len - skb->wire_len; // size of ethernet header
  bpf_skb_load_bytes(skb, in_off, &ipv4, sizeof(ipv4));

  bpf_printk("%s dev %s", dir, BPF_CORE_READ((struct sk_buff *)skb, dev, name));
  bpf_printk("%s size %d", dir, skb->len);
  if (skb->mark != 0) {
    bpf_printk("%s mark %d", dir, skb->mark);
  }
  print_ipv42(dir, "ipv4 src", ipv4.saddr);
  print_ipv42(dir, "ipv4 dst", ipv4.daddr);
}

#ifndef BPF_TRACE
#define print_ipv4(...)
#define print_mac(...)
#define dump_sock(...)
#endif

#define _cleanup(f) __attribute__((cleanup(f)))

typedef struct ScopeTime ScopeTime;
struct ScopeTime {
  u64 start;
  const char *message;
};

[[maybe_unused]]
static __always_inline ScopeTime scope_time__new(const char *msg) {
  return (ScopeTime){
      .start = bpf_ktime_get_ns(),
      .message = msg,
  };
}

[[maybe_unused]]
static __always_inline void scope_time__report_ns(ScopeTime *t) {
  u64 now = bpf_ktime_get_ns();
  __bpf_vprintk("Done %s() in %u ns", t->message, now - t->start);
}

#define trace_time_init(msg) struct ScopeTime _st = scope_time__new(msg);

#define trace_time_report() scope_time__report_ns(&_st);

#define trace_time(_msg)                                                       \
  struct ScopeTime _cleanup(scope_time__report_ns) _st = scope_time__new(_msg);

#define trace_time_fn() trace_time(__FUNCTION__)

#if !BPF_TRACE && !BPF_TRACE_TIME
#define trace_time(_msg)
#endif

#endif

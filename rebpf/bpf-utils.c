#ifndef BPF_UTILS_C
#define BPF_UTILS_C

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf-shared.h"

static bool ONLY_BASENAME_MATCHES;
static u32 NMATCHES;
static Match MATCHES_BUF[MATCHES_BUF_MAX];
static u32 STRINGS_LEN;
static char STRINGS_BUF[STRINGS_BUF_MAX];

typedef struct MatchCtx MatchCtx;
struct MatchCtx {
  const char *path;
  const char *basename;
  u32 path_len;
  u32 basename_len;
  u32 uid;
};

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
#define bpf_printk(...)
#define print_ipv4(...)
#define print_mac(...)
#define dump_sock(...)
#endif

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __uint(key_size, 4);
  __uint(value_size, PATH_MAX);
} path_buf SEC(".maps");

static char *read_path_buf(const struct file *file) {
  u32 i = 0;

  char *buf = bpf_map_lookup_elem(&path_buf, &i);
  if (!buf) {
    return NULL;
  }

  buf[PATH_MAX - 1] = '\0';
  ssize_t off = PATH_MAX - 1;

  const struct dentry *dent = file->f_path.dentry;
  struct bpf_dynptr ptr;
  bpf_dynptr_from_mem(buf, PATH_MAX - 1, 0, &ptr);

  bpf_for(i, 0, PATH_MAX) {
    const char *name = (const char *)dent->d_name.name;
    ssize_t len = bpf_strlen(name);
    if (len < 0 || off <= 0) {
      return NULL;
    }

    if (len > off) {
      len = off;
    }
    off -= len;

    // Make the verifier happy
    bpf_probe_read_kernel_dynptr(&ptr, off, len, name);

    if (off <= 0) {
      break;
    }

    off -= 1;
    buf[off] = '/';

    const struct dentry *par = dent->d_parent;
    if (par == NULL || dent == par) {
      off += 2;
      break;
    }

    dent = par;
  }

  return &buf[off];
}

static void match_ctx_init(MatchCtx *ctx, u32 uid, const char *path) {
  int len = bpf_strlen(path);
  if (len < 0) {
    len = 0;
  }
  int pref = bpf_strrchr(path, '/');
  if (pref < 0) {
    pref = 0;
  }

  *ctx = (MatchCtx){
      .uid = uid,
      .path = path,
      .path_len = len,
      .basename = pref ? path + pref + 1 : path,
      .basename_len = pref ? len - pref - 1 : len,
  };
}

static int match_ctx_match(const MatchCtx *ctx, const Match *match) {
  if (match->uid != 0 && match->uid != ctx->uid) {
    bpf_printk("Comparing basename '%s': different uid", ctx->basename);
    return 0;
  }

  int off = match->pat_off;
  if (off > sizeof(STRINGS_BUF)) {
    return 0;
  }
  const char *pat = STRINGS_BUF + off;

  bpf_printk("Comparing basename '%s' against '%s'", ctx->basename, pat);

  switch (match->kind) {
  case MATCH_KIND_BASENAME:
    return ctx->basename_len == match->pat_len &&
           bpf_strcmp(ctx->basename, pat) == 0;
  case MATCH_KIND_FULL:
    return ctx->path_len == match->pat_len && bpf_strcmp(ctx->path, pat) == 0;
  case MATCH_KIND_SUBSTR:
    return ctx->path_len >= match->pat_len && bpf_strstr(ctx->path, pat) >= 0;
  case MATCH_KIND_PREFIX:
    return ctx->path_len >= match->pat_len && bpf_strstr(ctx->path, pat) == 0;
  default:
    return 0;
  }
}

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

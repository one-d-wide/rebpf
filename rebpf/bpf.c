#define BPF

#include <bpf/libbpf_version.h>

#if LIBBPF_MAJOR_VERSION > 1 ||                                                \
    (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION > 6)
#include "vmlinux.h"
#else
// libbpf 1.6 exports a symbol incompatible with one in vmlinux.h
#define bpf_stream_vprintk __bpf_stream_vprintk
#include "vmlinux.h"
#undef bpf_stream_vprintk
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf-shared.h"
#include "bpf-utils.c"

#define AF_INET 2
#define AF_INET6 10

char _license[] SEC("license") = "GPL";

static BpfConfig CONFIG;
static Stats STATS;

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, NAT_CACHE_MAX);
  __uint(key_size, sizeof(NatKey));
  __uint(value_size, sizeof(NatVal));
} nat_cache SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TASK_CACHE_MAX);
  __uint(key_size, sizeof(TaskId));
  __uint(value_size, sizeof(bool));
} task_cache SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  // Sockets above this limit will be rejected
  __uint(max_entries, SOCKET_CACHE_MAX);
  __uint(key_size, sizeof(u64));
  __uint(value_size, sizeof(bool));
} socket_cache SEC(".maps");

static bool needs_mark(struct task_struct *task, u32 uid);
static bool needs_mark_uncached(struct task_struct *task, u32 uid);
static int do_redirect(struct __sk_buff *skb, Redirect *from_dev,
                       Redirect *to_dev, bool is_ingress);

SEC("cgroup/sock_create")
int cgroup_socket_create(struct bpf_sock *ctx) {
  int family = ctx->family;
  if (family != AF_INET && family != AF_INET6) {
    return 1;
  }

  struct task_struct *task = (void *)bpf_get_current_task_btf();
  u32 uid = bpf_get_current_uid_gid();
  bpf_printk("cgroup/sock_create %s", task->comm);

  u64 cookie = bpf_get_socket_cookie(ctx);
  bpf_printk("%lx", cookie);

  // TODO: maybe leave a mark on the socket instead

  u8 val = 0;
  if (needs_mark(task, uid)) {
    bpf_map_update_elem(&socket_cache, &cookie, &val, BPF_NOEXIST);
  }

  return 1;
}

SEC("cgroup/sock_release")
int cgroup_socket_release(struct bpf_sock *ctx) {
  int family = ctx->family;
  if (family != AF_INET && family != AF_INET6) {
    return 1;
  }

  u64 cookie = bpf_get_socket_cookie(ctx);
  bpf_map_delete_elem(&socket_cache, &cookie);

  return 1;
}

static int dump_iter_file(struct bpf_iter__task_file *ctx, bool only_report) {
  struct task_struct *task = ctx->task;
  struct file *file = ctx->file;

  if (!task || !file) {
    return 0;
  }

  struct socket *sock = bpf_sock_from_file(file);
  if (!sock) {
    return 0;
  }

  struct sock *sk = sock->sk;
  if (!sk) {
    return 0;
  }

  int family = sk->__sk_common.skc_family;
  if (family != AF_INET && family != AF_INET6) {
    return 0;
  }

  u32 uid = task->cred->uid.val;
  u64 cookie = bpf_get_socket_cookie(sk);
  u8 val = 0;

  if (!needs_mark(task, uid)) {
    return 0;
  }

  if (only_report) {
    const struct file *file = task->mm->exe_file;
    if (!file) {
      return 0;
    }
    BPF_SEQ_PRINTF(ctx->meta->seq, "%s\n", file->f_path.dentry->d_name.name);
    return 0;
  }

  bpf_map_update_elem(&socket_cache, &cookie, &val, BPF_NOEXIST);

  return 0;
}

SEC("iter/task_file")
int refresh_sockets(struct bpf_iter__task_file *ctx) {
  return dump_iter_file(ctx, false);
}

SEC("iter/task_file")
int dump_socket_procs(struct bpf_iter__task_file *ctx) {
  return dump_iter_file(ctx, true);
}

static long delete_socket_callback(struct bpf_map *map, const void *key,
                                   void *value, void *ctx) {
  bpf_map_delete_elem(map, key);
  return 0;
}

static long delete_callback(struct bpf_map *map, const void *key, void *value,
                            void *ctx) {
  bpf_map_delete_elem(map, key);
  return 0;
}

SEC("syscall")
int get_stats(struct Stats *stats) {
  *stats = STATS;
  stats->time_ns = bpf_ktime_get_ns();

  STATS.rx_bytes = 0;
  STATS.tx_bytes = 0;

  return 0;
}

SEC("syscall")
int reload_config(struct BpfConfig *conf) {
  bool last_drop = CONFIG.drop;
  bool user_drop = conf->drop;
  u32 last_gen = CONFIG.generation;

  conf->drop = true;
  CONFIG = *conf;

  if (conf->generation == last_gen) {
    goto skip_copying_matches;
  }

  ONLY_BASENAME_MATCHES = true;
  NMATCHES = 0;

  int nmatches = conf->nmatches;
  if (nmatches > MATCHES_BUF_MAX) {
    goto err;
  }

  u32 off = 0;
  u32 i;
  bpf_for(i, 0, nmatches) {
    // Make verifier happy
    if (i > MATCHES_BUF_MAX) {
      goto err;
    }
    if (off >= STRINGS_BUF_MAX) {
      goto err;
    }

    MatchStr match = {0};
    if (bpf_probe_read_user(&match, sizeof(match), conf->matches + i)) {
      goto err;
    }

    ssize_t len = bpf_probe_read_user_str(STRINGS_BUF + off,
                                          STRINGS_BUF_MAX - off, match.pat);
    if (len <= 0) {
      goto err;
    }
    if (off + len == STRINGS_BUF_MAX) {
      goto err;
    }

    MATCHES_BUF[i] = (Match){
        .kind = match.kind,
        .dir = match.dir,
        .uid = match.uid,
        .pat_off = off,
        .pat_len = len - 1,
    };
    off += len;

    if (match.kind != MATCH_KIND_BASENAME) {
      ONLY_BASENAME_MATCHES = false;
    }
  }
  NMATCHES = nmatches;

  bpf_for_each_map_elem(&socket_cache, delete_socket_callback, NULL, 0);
  bpf_for_each_map_elem(&task_cache, delete_callback, NULL, 0);

skip_copying_matches:

  CONFIG.drop = last_drop;
  conf->drop = user_drop;
  return 0;

err:
  CONFIG.generation = last_gen;
  CONFIG.drop = last_drop;
  conf->drop = user_drop;
  return 1;
}

// SEC("tcx/egress")
// int trace_egress(struct __sk_buff *skb) {
//   dump_sock(skb, "egress");
//   return 0; // pass
// }
//
// SEC("tcx/ingress")
// int trace_ingress(struct __sk_buff *skb) {
//   dump_sock(skb, "ingress");
//   return 0; // pass
// }

SEC("tcx/ingress")
int ingress(struct __sk_buff *skb) {
  if (!CONFIG.enable) {
    return 0;
  }

  if (CONFIG.drop) {
    return TCX_DROP;
  }

  bpf_printk("tcx/ingress mark=%ld", skb->mark);
  __atomic_fetch_add(&STATS.rx_bytes, skb->wire_len, __ATOMIC_RELAXED);

  return do_redirect(skb, &CONFIG.to_dev, &CONFIG.from_dev, true);
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
  int family = skb->family;
  if (family != AF_INET && family != AF_INET6) {
    return 1;
  }

  if (!CONFIG.enable || skb->ifindex != CONFIG.from_dev.ifindex) {
    return 1;
  }

  if (CONFIG.drop) {
    return 0; // drop
  }

  u64 cookie = bpf_get_socket_cookie(skb);
  if (!bpf_map_lookup_elem(&socket_cache, &cookie)) {
    bpf_printk("egress socket not tracked mark=%ld to_ifi=%ld", skb->mark,
               skb->ifindex);
    return 1;
  }

  // TODO: maybe leave a mark on the socket instead
  skb->mark = CONFIG.mark;

  return 1; // allow
}

SEC("tcx/egress")
int egress(struct __sk_buff *skb) {
  if (!CONFIG.enable || skb->mark != CONFIG.mark) {
    return TCX_PASS;
  }

  bpf_printk("tcx/egress mark=%ld", skb->mark);
  __atomic_fetch_add(&STATS.tx_bytes, skb->wire_len, __ATOMIC_RELAXED);

  return do_redirect(skb, &CONFIG.from_dev, &CONFIG.to_dev, false);
}

static bool needs_mark_shallow(struct task_struct *task, u32 uid) {
  TaskId taskid = {
      .pid = task->pid,
      .time = task->start_boottime,
  };

  u8 *cached_res = bpf_map_lookup_elem(&task_cache, &taskid);
  if (cached_res) {
    return *cached_res;
  }

  u8 res = needs_mark_uncached(task, uid);

  bpf_map_update_elem(&task_cache, &taskid, &res, BPF_ANY);

  return res;
}

// WIP. Scan current process and its parent processes for a match.
[[maybe_unused]]
static bool needs_mark_descend(struct task_struct *task, u32 uid) {
  TaskId taskid = {
      .pid = task->pid,
      .time = task->start_boottime,
  };

  u8 *cached_res = bpf_map_lookup_elem(&task_cache, &taskid);
  if (cached_res) {
    return *cached_res;
  }

  u8 res = false;
  int i = 0;
  bpf_for(i, 0, DESCEND_MAX) {
    bpf_printk("TASK %d %d %s", i, task->pid, task->comm);

    // Check if task at hand is marked
    res = needs_mark_uncached(task, uid);
    if (res) {
      break;
    }

    // Check if we already sweeped its parent task
    struct task_struct *par = task->real_parent;
    if (task->pid == 1 || !par || task == par) {
      res = false;
      break;
    }

    TaskId par_id = {
        .pid = par->pid,
        .time = par->start_boottime,
    };

    u8 *cached_res = bpf_map_lookup_elem(&task_cache, &par_id);
    if (cached_res) {
      bpf_printk("PARENT CACHED %d %d %s", i, par->pid, par->comm);
      res = *cached_res;
      break;
    }

    // Move the parent task
    // BPF doesn't seem to really allow using arrays of pointers/recursion
    // without upsetting the verifier, so we will just update one at a time.
    // This will increase number of uncached checksfrom O(n) to O(height*n)
    // (worst case) In practice though, not many processes use IP network, so n
    // should be small.
    task = par;
  }

  taskid = (TaskId){
      .pid = task->pid,
      .time = task->start_boottime,
  };

  // We can't build a proper stack, so we will just buld
  if (bpf_map_update_elem(&task_cache, &taskid, &res, BPF_ANY)) {
    bpf_printk("err updating task cache");
  }

  return res;
}

inline static bool needs_mark(struct task_struct *task, u32 uid) {
  //   if (CONFIG.check_parents) {
  //     return needs_mark_descend(task, uid);
  //   } else {
  //     return needs_mark_shallow(task, uid);
  //   }

  return needs_mark_shallow(task, uid);
}

static bool needs_mark_uncached(struct task_struct *task, u32 uid) {
  struct file *file = task->mm->exe_file;

  if (!file) {
    bpf_printk("task doesn't have a file %s", task->comm);
    return false;
  }

  const char *path;
  if (ONLY_BASENAME_MATCHES) {
    path = (char *)file->f_path.dentry->d_name.name;
  } else {
    path = read_path_buf(file);
  }

  if (!path) {
    bpf_printk("err path d path", task->comm);
    return false;
  }

  MatchCtx ctx;
  match_ctx_init(&ctx, uid, path);

  bool res = false;
  u32 i = 0;
  bpf_for(i, 0, MIN(NMATCHES, ARRAY_LEN(MATCHES_BUF))) {
    if ((res = match_ctx_match(&ctx, &MATCHES_BUF[i]) != 0)) {
      break;
    }
  }

  if (res) {
    return MATCHES_BUF[i].dir == MATCH_DIR_REDIRECT;
  }

  return false;
}

#define SKB_BUF_MAX (1u << 15) // (1 << 16) - sizeof

static int do_redirect(struct __sk_buff *skb, Redirect *from_dev,
                       Redirect *to_dev, bool is_ingress) {
  bpf_printk("DO_REDIRECT");
  bpf_printk("do_redirect mark=%ld to_ifi=%ld len=%ld", skb->mark,
             to_dev->ifindex, skb->wire_len);
  print_ipv4("do_redirect to_addr", to_dev->addr[0]);

  u64 data_off = BPF_CORE_READ(((struct sk_buff *)skb), data) -
                 BPF_CORE_READ(((struct sk_buff *)skb), head);
  u64 eth_off = BPF_CORE_READ(((struct sk_buff *)skb), mac_header) - data_off;
  u64 iph_off =
      BPF_CORE_READ(((struct sk_buff *)skb), network_header) - data_off;
  u64 tr_off =
      BPF_CORE_READ(((struct sk_buff *)skb), transport_header) - data_off;

  // Make the verifier happy
  if (eth_off > (1 << 15) || iph_off > (1 << 15)) {
    bpf_printk("oops, got invalid header len");
    return TCX_PASS;
  }

  if (eth_off == iph_off && to_dev->set_l2) {
    // To-device is L2 device and needs an ethernet header, which the current
    // skb doesn't have it. We should allocate one

    bpf_printk("alloc mac");

    if (bpf_skb_change_head(skb, sizeof(struct ethhdr), 0)) {
      bpf_printk("no eth allocated");
      return TCX_PASS;
    }
    iph_off += sizeof(struct ethhdr);
    tr_off += sizeof(struct ethhdr);

    bpf_skb_store_bytes(skb, eth_off + offsetof(struct ethhdr, h_proto),
                        (char[]){0x08, 0x00}, 2, 0); // Ipv4 magic
  }

  // Make the verifier happy
  void *data = (void *)(long)skb->data;
  if (data + eth_off + sizeof(struct ethhdr) > (void *)(long)skb->data_end ||
      data + iph_off + sizeof(struct iphdr) > (void *)(long)skb->data_end) {
    bpf_printk("oops, got invalid header len");
    return 0;
  }

  if (CONFIG.allow_lan) {
    struct iphdr *iph = data + iph_off;
    if ((*(u8 *)iph) >> 4 != 0x4) {
      bpf_printk("wrong ip ver 0x%x", (*(u8 *)iph) >> 4);
      return 0;
    }

    Redirect *f_dev;
    Redirect *t_dev;

    if (is_ingress) {
      f_dev = from_dev;
      t_dev = to_dev;
    } else {
      f_dev = to_dev;
      t_dev = from_dev;
    }

    // We don't implement a stateful connection tracking, so have to assume all
    // ingress traffic is a response to a redirected exchange. Which
    // isn't always the case, e.g. when talking to a LAN device.

    struct bpf_fib_lookup l = {
        .ifindex = f_dev->ifindex,
        .family = AF_INET,
        .ipv4_src = f_dev->addr[0],
        .ipv4_dst = iph->saddr,
    };

    if (!is_ingress) {
      l.ipv4_dst = iph->daddr;
    }

    print_ipv4("probing saddr ", l.ipv4_src);
    print_ipv4("probing daddr ", l.ipv4_dst);

    // TODO: direct + table id?
    long res = bpf_fib_lookup(skb, &l, sizeof(l), 0);

    print_ipv4("preferred saddr ", l.ipv4_src);
    print_ipv4("preferred daddr ", l.ipv4_dst);

    bpf_printk("res: %ld", res);
    bpf_printk("ifindex: %u", l.ifindex);

    print_mac("smac ", l.smac);
    print_mac("dmac ", l.dmac);

    if (!res && l.ifindex != t_dev->ifindex) {
      bpf_printk("FOUND LAN (different interface)");
      return TCX_PASS;
    }

    bpf_printk("f_dev next mac set=%i", f_dev->set_nexthop_mac);
    print_mac("f_dev next mac", f_dev->nexthop_mac);
    bpf_printk("t_dev next mac set=%i", t_dev->set_nexthop_mac);
    print_mac("t_dev next mac", t_dev->nexthop_mac);

    if (!res && t_dev->set_nexthop_mac &&
        __builtin_memcmp(t_dev->nexthop_mac, l.dmac, 6)) {
      bpf_printk("FOUND LAN (different nexthop mac)");
      return TCX_PASS;
    }
  }

  struct ethhdr *eth = data + eth_off;

  if (eth_off != iph_off) {
    if (eth->h_proto != bpf_htons(0x0800)) {
      bpf_printk("wrong eth proto 0x%04x", bpf_htons(eth->h_proto));
      return 0;
    }

    print_mac("orig dmac", eth->h_dest);
    print_mac("orig smac", eth->h_source);

    print_mac("to_dev mac", to_dev->mac);

    if (is_ingress) {
      __builtin_memcpy(eth->h_dest, to_dev->mac, sizeof(to_dev->mac));
      if (to_dev->set_nexthop_mac) {
        __builtin_memcpy(eth->h_source, to_dev->nexthop_mac,
                         sizeof(to_dev->mac));
      } else {
        __builtin_memset(eth->h_source, 0, sizeof(eth->h_source));
      }
    } else {
      __builtin_memcpy(eth->h_source, to_dev->mac, sizeof(to_dev->mac));
      if (to_dev->set_nexthop_mac) {
        __builtin_memcpy(eth->h_dest, to_dev->nexthop_mac, sizeof(to_dev->mac));
      } else {
        __builtin_memset(eth->h_dest, 0, sizeof(eth->h_source));
      }
    }

    print_mac("new dmac", eth->h_dest);
    print_mac("new smac", eth->h_source);
  }

  // TODO: handle ipv6
  struct iphdr *iph = data + iph_off;
  if ((*(u8 *)iph) >> 4 != 0x4) {
    bpf_printk("wrong ip version 0x%x", (*(u8 *)iph) >> 4);
    return TCX_PASS;
  }

  u8 ipproto = iph->protocol;
  u32 old_addr;
  u32 new_addr = to_dev->addr[0];

  bpf_printk("REDIRECTING %s", is_ingress ? "(ingress)" : "(egress)");

  if (is_ingress) {
    old_addr = iph->daddr;
    iph->daddr = new_addr;
  } else {
    old_addr = iph->saddr;
    iph->saddr = new_addr;
  }

  print_ipv4("new saddr", iph->saddr);
  print_ipv4("new daddr", iph->daddr);

  u32 l4_csum_off = 0;
  switch (ipproto) {
  case IPPROTO_TCP:
    l4_csum_off = tr_off + offsetof(struct tcphdr, check);
    break;
  case IPPROTO_UDP:
    l4_csum_off = tr_off + offsetof(struct udphdr, check);
    break;
  case IPPROTO_ICMP:
  default:
    // ICMP and other protocols don't include IP header in checksum calculation
    break;
  }

  if (!CONFIG.spoof_dns) {
    goto skip_dns;
  }

  if (ipproto != IPPROTO_TCP && ipproto != IPPROTO_UDP) {
    goto skip_dns;
  }

  if (tr_off > (1 << 15) || data + tr_off + 4 > (void *)(long)skb->data_end) {
    goto skip_dns;
  }

  u8 *trh = data + tr_off;
  u16 sport = *(u16 *)trh;
  u16 dport = *(u16 *)(trh + 2);

  if (is_ingress) {
    if (sport != bpf_htons(DNS_PORT)) {
      goto skip_dns;
    }

    bpf_printk("spoofing dns");

    struct NatKey k = {
        .remote_ip = iph->saddr,
        .remote_port = sport,
        .local_ip = old_addr,
        .local_port = dport,
    };

    print_ipv4("dns from ", iph->saddr);
    bpf_printk("port %u", bpf_htons(sport));
    print_ipv4("dns to ", old_addr);
    bpf_printk("port %u", bpf_htons(dport));

    u32 *spoofed_saddr = bpf_map_lookup_elem(&nat_cache, &k);
    if (!spoofed_saddr) {
      bpf_printk("dns request not found");
      goto skip_dns;
    }

    print_ipv4("dns request found to ", *spoofed_saddr);
    bpf_printk("dns local port %u", dport);

    u32 old_saddr = iph->saddr;
    u32 new_saddr = *spoofed_saddr;
    iph->saddr = new_saddr;

    bpf_l3_csum_replace(skb,
                        sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                        old_saddr, new_saddr, 4);

    if (l4_csum_off != 0) {
      bpf_l4_csum_replace(skb, l4_csum_off, old_saddr, new_saddr,
                          4 | BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
    }

  } else {
    if (dport != bpf_htons(DNS_PORT)) {
      goto skip_dns;
    }

    bpf_printk("spoofing dns");

    u32 old_daddr = iph->daddr;
    u32 new_daddr = CONFIG.spoof_dns_ipv4;
    iph->daddr = new_daddr;

    print_ipv4("dns to ", old_daddr);
    bpf_printk("dport %u", bpf_htons(dport));
    bpf_printk("sport %u", bpf_htons(sport));

    struct NatKey k = {
        .remote_ip = new_daddr,
        .remote_port = dport,
        .local_ip = new_addr,
        .local_port = sport,
    };

    bpf_map_update_elem(&nat_cache, &k, &old_daddr, BPF_ANY);

    bpf_l3_csum_replace(skb,
                        sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                        old_daddr, new_daddr, 4);

    if (l4_csum_off != 0) {
      bpf_l4_csum_replace(skb, l4_csum_off, old_daddr, new_daddr,
                          4 | BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
    }
  }

skip_dns:

  bpf_l3_csum_replace(skb,
                      sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                      old_addr, new_addr, 4);

  if (l4_csum_off != 0) {
    bpf_l4_csum_replace(skb, l4_csum_off, old_addr, new_addr,
                        4 | BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
  }

  return bpf_redirect(to_dev->ifindex, is_ingress ? BPF_F_INGRESS : 0);
}

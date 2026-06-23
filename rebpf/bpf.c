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

#ifndef BPF_TRACE
#define bpf_printk(...)
#endif

#include "bpf-dfa.c"
#include "bpf-shared.h"

#define AF_INET 2
#define AF_INET6 10

char _license[] SEC("license") = "GPL";

BpfConfig CONFIG;

bool HAS_DFA;
DFA MASTER_DFA;

typedef struct MatchRes MatchRes;
struct MatchRes {
  u32 redirect; // 0 => bypass, 1 => redirect
  u32 table_off;
  u32 table_len;
};

typedef struct MatchCtx MatchCtx;
struct MatchCtx {
  u32 uid;
  DFA dfa;
  MatchRes res;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TASK_CACHE_MAX);
  __uint(key_size, sizeof(TaskId));
  __uint(value_size, sizeof(MatchRes));
} task_cache SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 65536 * 2);
} dns_ringbuf SEC(".maps");

static int needs_mark(struct task_struct *task, MatchCtx *m);
static int needs_mark_uncached(struct task_struct *task, MatchCtx *m);

SEC("cgroup/sock_create")
int cgroup_socket_create(struct bpf_sock *ctx) {
  if (!CONFIG.enable) {
    return 1;
  }

  int family = ctx->family;
  if (family != AF_INET && family != AF_INET6) {
    return 1;
  }

  struct task_struct *task = (void *)bpf_get_current_task_btf();
  u32 uid = bpf_get_current_uid_gid();
  bpf_printk("cgroup/sock_create %s", task->comm);

  if (!HAS_DFA) {
    bpf_printk("DFA not setup");
    return 1;
  }

  MatchCtx m = {
      .uid = uid,
      .dfa = MASTER_DFA,
  };

  if (needs_mark(task, &m) <= 0) {
    return 1;
  }

#define SOL_SOCKET 1
#define SO_MARK 36

  bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &CONFIG.mark, sizeof(CONFIG.mark));

  return 1;
}

static int dump_iter_file(struct bpf_iter__task_file *ctx, bool procfd) {
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

  if (!HAS_DFA) {
    bpf_printk("DFA not setup");
    return 0;
  }

  MatchCtx m = {
      .uid = task->cred->uid.val,
      .dfa = MASTER_DFA,
  };

  if (needs_mark(task, &m) < 0) {
    return 0;
  }

  if (procfd) {
    if (!m.res.redirect) {
      return 0;
    }
    struct ProcFdEntry ent = {
        .pid = task->pid,
        .start_boottime = task->start_boottime,
        .fd = ctx->fd,
    };
    bpf_seq_write(ctx->meta->seq, &ent, sizeof(ent));
    return 0;
  }

  const struct file *exe_file = task->mm->exe_file;
  if (!file) {
    return 0;
  }

  struct seq_file *seq = ctx->meta->seq;
  const u8 *name = exe_file->f_path.dentry->d_name.name;
  u32 len = exe_file->f_path.dentry->d_name.len;

  u32 __arena *match_id_table =
      (u32 __arena *)(get_arena() + m.dfa.match_id_table_off);

  bpf_printk("State %u, table_off=%u, table_len=%u", m.dfa.start,
             m.res.table_off, m.res.table_len);

  int i;
  bpf_for(i, 0, m.res.table_len) {
    u32 pat_id = match_id_table[m.res.table_off + i];
    bpf_printk("State %u, pat_id=%u", m.dfa.start, pat_id);

    bpf_seq_write(seq, &pat_id, sizeof(pat_id));
    bpf_seq_write(seq, &len, sizeof(len));
    BPF_SEQ_PRINTF(seq, "%s", name);
  }

  return 0;
}

SEC("iter/task_file")
int refresh_sockets(struct bpf_iter__task_file *ctx) {
  return dump_iter_file(ctx, true);
}

SEC("iter/task_file")
int dump_socket_procs(struct bpf_iter__task_file *ctx) {
  return dump_iter_file(ctx, false);
}

static long delete_callback(struct bpf_map *map, const void *key, void *value,
                            void *ctx) {
  bpf_map_delete_elem(map, key);
  return 0;
}

SEC("syscall")
int reload_config(struct BpfConfig *conf) {
  if (!BASE || BASE_PAGES < conf->arena_npages) {
    if (BASE) {
      bpf_arena_free_pages(&arena, BASE, BASE_PAGES);
    }
    BASE_PAGES = conf->arena_npages;
    BASE = bpf_arena_alloc_pages(&arena, NULL, BASE_PAGES, NUMA_NO_NODE, 0);
  }

  bpf_for_each_map_elem(&task_cache, delete_callback, NULL, 0);
  return 0;
}

static int needs_mark(struct task_struct *task, MatchCtx *m) {
  TaskId taskid = {
      .pid = task->pid,
      .time = task->start_boottime,
  };

  MatchRes *cached_res = bpf_map_lookup_elem(&task_cache, &taskid);
  if (cached_res) {
    m->res = *cached_res;
    return m->res.redirect;
  }

  if (needs_mark_uncached(task, m) < 0) {
    return -1;
  }

  bpf_map_update_elem(&task_cache, &taskid, &m->res, BPF_ANY);
  return m->res.redirect;
}

static int needs_mark_uncached(struct task_struct *task, MatchCtx *m) {
  trace_time("needs_mark_uncached");

  struct file *file = task->mm->exe_file;

  if (!file) {
    bpf_printk("task doesn't have a file %s", task->comm);
    return -1;
  }

  DFA *dfa = &m->dfa;
  if (!match_regex_rev_path(file, dfa)) {
    return -1;
  }

  u32 this = dfa->start;
  if (this < dfa->fin_min || dfa->fin_max < this) {
    return -1;
  }

  u8 __arena *arena = get_arena();
  u32 __arena *slices = (u32 __arena *)(arena + dfa->match_slices_off);
  u8 __arena *redirect_table = (u8 __arena *)(arena + dfa->redirect_table_off);
  u32 __arena *uid_table = (u32 __arena *)(arena + dfa->uid_table_off);

  u32 off = this - dfa->fin_min;

  bpf_printk("slices %u", dfa->match_slices_off);
  bpf_printk("State %u, off=%u", this, off);

  u32 table_off = slices[off * 2];
  u32 table_len = slices[off * 2 + 1];

  m->res = (MatchRes){
      .redirect = redirect_table[off],
      .table_off = table_off,
      .table_len = table_len,
  };

  bpf_printk("State %u, table_off=%u, table_len=%u", this, table_off,
             table_len);

  int i;
  bpf_for(i, 0, table_len) {
    int uid = uid_table[table_off + i];

    bpf_printk("State %u, uid=%u", this, uid);
    if (uid == 0 || uid == m->uid) {
      return m->res.redirect;
    }
  }

  return -1;
}

SEC("cgroup_skb/ingress")
int ingress(struct __sk_buff *skb) {
  if (!CONFIG.enable_dns) {
    return 1;
  }

  if (skb->vlan_present) {
    return 1;
  }

  if (skb->family != AF_INET) {
    return 1;
  }

  if (skb->remote_port != bpf_ntohl(53) && skb->remote_port != bpf_ntohl(0)) {
    return 1;
  }

  bpf_printk("cgroup_skb/ingress mark=%ld sport=%ld", skb->mark,
             bpf_ntohl(skb->remote_port));

  trace_time_fn();

  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  struct iphdr *ip = data;
  if ((void *)(ip + 1) > data_end) {
    return 1;
  }

  if (ip->protocol != IPPROTO_UDP) {
    return 1;
  }

  struct udphdr *udp = (void *)ip + ip->ihl * 4;
  if ((void *)(udp + 1) > data_end) {
    return 1;
  }

  if (udp->source != bpf_htons(53)) {
    return 1;
  }

  void *dns = (void *)(udp + 1);
  u32 dns_len = data_end - dns;
  u32 dns_off = dns - data;

  struct bpf_dynptr ptr_ring = {};
  struct bpf_dynptr ptr_skb = {};

  bpf_ringbuf_reserve_dynptr(&dns_ringbuf, dns_len, 0, &ptr_ring);

  bpf_dynptr_from_skb(skb, 0, &ptr_skb);

  bpf_dynptr_copy(&ptr_ring, 0, &ptr_skb, dns_off, dns_len);

  bpf_ringbuf_submit_dynptr(&ptr_ring, 0);

  return 1;
}

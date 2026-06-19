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

SEC("cgroup/sock_create")
int cgroup_socket_create(struct bpf_sock *ctx) {
  int family = ctx->family;
  if (family != AF_INET && family != AF_INET6) {
    return 1;
  }

  if (!CONFIG.enable) {
    return 1;
  }

  struct task_struct *task = (void *)bpf_get_current_task_btf();
  u32 uid = bpf_get_current_uid_gid();
  bpf_printk("cgroup/sock_create %s", task->comm);

  if (!needs_mark(task, uid)) {
    return 1;
  }

#define SOL_SOCKET 1
#define SO_MARK 36

  bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &CONFIG.mark, sizeof(CONFIG.mark));

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

  struct ProcFdEntry ent = {
      .pid = task->pid,
      .start_boottime = task->start_boottime,
      .fd = ctx->fd,
  };
  bpf_seq_write(ctx->meta->seq, &ent, sizeof(ent));

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

static long delete_callback(struct bpf_map *map, const void *key, void *value,
                            void *ctx) {
  bpf_map_delete_elem(map, key);
  return 0;
}

SEC("syscall")
int reload_config(struct BpfConfig *conf) {
  u32 last_gen = CONFIG.generation;
  CONFIG = *conf;

  if (conf->generation == last_gen) {
    goto skip_cloning_matches;
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

    if (match.kind != MATCH_KIND_BASENAME && match.kind < __MATCH_KIND_MAX) {
      ONLY_BASENAME_MATCHES = false;
    }
  }
  NMATCHES = nmatches;

  bpf_for_each_map_elem(&task_cache, delete_callback, NULL, 0);

skip_cloning_matches:
  return 0;

err:
  CONFIG.generation = last_gen;
  return 1;
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

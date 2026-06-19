#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf-shared.h"
#include "bpf.skel.c"

#define LOG1(fmt) printf(fmt "\n");
#define LOG(fmt, ...) printf(fmt "\n", __VA_ARGS__);

#define LOG_ERRNO(fmt, ...) LOG(fmt ": %s\n", __VA_ARGS__, strerror(errno));
#define LOG1_ERRNO(fmt) LOG(fmt ": %s\n", strerror(errno));

#define ERROR1(fmt) fprintf(stderr, "ERROR: %s: " fmt "\n", __func__);
#define ERROR(fmt, ...)                                                        \
  fprintf(stderr, "ERROR: %s: " fmt "\n", __func__, __VA_ARGS__);

#define ERROR_ERRNO(fmt, ...) ERROR(fmt ": %s\n", __VA_ARGS__, strerror(errno));

#define EXPECT(expr)                                                           \
  {                                                                            \
    if (!(expr)) {                                                             \
      ERROR_ERRNO("%s", #expr)                                                 \
      exit(1);                                                                 \
    }                                                                          \
  }
#define EXPECT0(expr) EXPECT(expr == 0)

#define FATAL0()                                                               \
  ERROR1("unreachable");                                                       \
  exit(1);
#define FATAL1(fmt)                                                            \
  ERROR1(fmt);                                                                 \
  exit(1);
#define FATAL(...)                                                             \
  ERROR(__VA_ARGS__);                                                          \
  exit(1);
#define FATAL_ERRNO(...)                                                       \
  ERROR_ERRNO(__VA_ARGS__);                                                    \
  exit(1);

#define _cleanup(f) __attribute__((cleanup(f)))

[[maybe_unused]]
static void freep(void **ptr) {
  if (*ptr) {
    free(*ptr);
  }
}

[[maybe_unused]]
static void closep(int *ptr) {
  if (*ptr) {
    close(*ptr);
  }
}

[[maybe_unused]]
static void fclosep(FILE **ptr) {
  if (*ptr) {
    fclose(*ptr);
  }
}

const u64 NS_IN_SEC = 1000000000;

static struct bpf *skel = NULL;
static struct {
  int reload_config_fd;
  struct bpf_link *iter_file;
  int iter_file_fd;
  struct bpf_link *dump_socket_procs_file;
  int dump_socket_procs_fd;
  u64 last_gen;
  u32 last_mark;
} links = {0};

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Read starttime from /proc/<pid>/stat, see proc_pid_stat(5)
u64 proc_get_start_time(pid_t pid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%llu/stat", pid);

  FILE *file _cleanup(fclosep) = fopen(path, "r");
  if (!file) {
    return 0;
  }

  char buf[1024];
  if (!fgets(buf, sizeof(buf), file)) {
    return 0;
  }

  const char *seek = strrchr(buf, ')');
  for (int i = 0; *seek && i < 20; ++i) {
    seek = strchr(seek + 1, ' ');
  }

  return strtoull(seek, NULL, 10) / sysconf(_SC_CLK_TCK);
}

const char *proc_set_mark(pid_t pid, u64 start_time, int fd, u32 fwmark) {
  int pidfd _cleanup(closep) = syscall(SYS_pidfd_open, pid, 0);
  if (pidfd < 0) {
    return strerror(errno);
  }

  int cloned_fd _cleanup(closep) = syscall(SYS_pidfd_getfd, pidfd, fd, 0);
  if (cloned_fd < 0) {
    return strerror(errno);
  }

  if (proc_get_start_time(pid) != start_time) {
    return "Mismatch in starttime";
  }

  int res = setsockopt(cloned_fd, SOL_SOCKET, SO_MARK, &fwmark, sizeof(fwmark));
  if (res < 0) {
    return strerror(errno);
  }

  return NULL;
}

void bpf_drop_caps() {
  if (getuid() == 0) {
    uid_t nobody = 65534;
    EXPECT0(setresgid(nobody, nobody, nobody));
    EXPECT0(setresuid(nobody, nobody, nobody));
    EXPECT(getuid() != 0 && geteuid() != 0);
  }

  cap_t caps = cap_get_proc();
  cap_clear(caps);
  EXPECT0(cap_set_proc(caps));
  cap_free(caps);
  EXPECT0(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
}

void bpf_init() {
  struct rlimit rlim_old = {0};
  EXPECT(getrlimit(RLIMIT_MEMLOCK, &rlim_old) == 0);

  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };
  EXPECT(setrlimit(RLIMIT_MEMLOCK, &rlim_new) == 0);

  EXPECT((skel = bpf__open()) != 0);

  clock_t s = clock();
  EXPECT(bpf__load(skel) == 0);
  LOG("bpf__load() in %f seconds\n", (float)(clock() - s) / CLOCKS_PER_SEC);

  int cgroup_fd _cleanup(closep) = -1;
  EXPECT((cgroup_fd = open("/sys/fs/cgroup/", O_RDONLY)) >= 0);
  EXPECT(bpf_program__attach_cgroup(skel->progs.cgroup_socket_create,
                                    cgroup_fd) != 0);
  EXPECT(links.iter_file =
             bpf_program__attach_iter(skel->progs.refresh_sockets, NULL));
  links.iter_file_fd = bpf_link__fd(links.iter_file);

  EXPECT(links.dump_socket_procs_file =
             bpf_program__attach_iter(skel->progs.dump_socket_procs, NULL));
  links.dump_socket_procs_fd = bpf_link__fd(links.dump_socket_procs_file);

  links.reload_config_fd = bpf_program__fd(skel->progs.reload_config);

  EXPECT(bpf_program__attach_cgroup(skel->progs.ingress, cgroup_fd));

  EXPECT(setrlimit(RLIMIT_MEMLOCK, &rlim_old) == 0);
}

void bpf_run_dns_ringbuf(int (*callback)(void *ctx, void *data, size_t data_sz),
                         void *ctx) {
  struct ring_buffer *rb;
  EXPECT((rb = ring_buffer__new(bpf_map__fd(skel->maps.dns_ringbuf), callback,
                                ctx, NULL)));

  while (1) {
    int err = ring_buffer__poll(rb, -1);
    if (err < 0 && errno == EINTR) {
      continue;
    }
    EXPECT(err >= 0);
  }
}

int bpf_reload_config(BpfConfig *conf) {
  struct bpf_test_run_opts run_opts = {
      .sz = sizeof(run_opts),
      .ctx_in = conf,
      .ctx_size_in = sizeof(*conf),
  };

  EXPECT(bpf_prog_test_run_opts(links.reload_config_fd, &run_opts) == 0);
  EXPECT0(run_opts.retval);

  if (links.last_gen == conf->generation && links.last_mark == conf->mark) {
    return 0;
  }

  links.last_gen = conf->generation;
  links.last_mark = conf->mark;

  int iter_fd _cleanup(closep) = -1;
  EXPECT((iter_fd = bpf_iter_create(links.iter_file_fd)) >= 0);

  int err;
  while (true) {
    struct ProcFdEntry buf[64];
    while ((err = read(iter_fd, buf, sizeof(buf))) == -1 && errno == EAGAIN)
      ;

    if (err <= 0) {
      break;
    }

    for (size_t i = 0; i < err / sizeof(*buf); ++i) {
      struct ProcFdEntry *ent = &buf[i];
      const char *err = proc_set_mark(ent->pid, ent->start_boottime / NS_IN_SEC,
                                      ent->fd, conf->mark);
      if (err) {
        ERROR("Setting fwmark on pid=%i fd=%i: %s", ent->pid, ent->fd, err);
      }
    }
  }

  EXPECT(err == 0);

  return 0;
}

void bpf_get_proc_names(char **ptr, u64 *len, u64 *cap) {
  int iter_fd _cleanup(closep) = -1;
  EXPECT((iter_fd = bpf_iter_create(links.dump_socket_procs_fd)) >= 0);

  *len = 1;
  ssize_t res = 0;
  do {
    *len += res;
    if (*len >= *cap) {
      *cap = *cap ? (*cap) * 2 : 2048;
      *ptr = realloc(*ptr, *cap);
    }
  } while ((res = read(iter_fd, *ptr + *len - 1, *cap - *len)) > 0);
  (*ptr)[*len - 1] = '\0';
  EXPECT(res >= 0);
}

static void iterate_map_batch(int map_fd, void *keys, size_t key_size,
                              void *vals, size_t value_size, size_t num,
                              size_t *len) {
  struct bpf_map_info info = {};
  u32 info_len = sizeof(info);
  int err;

  EXPECT0(bpf_obj_get_info_by_fd(map_fd, &info, &info_len));

  EXPECT(info.key_size == key_size);
  EXPECT(info.value_size == value_size);

  u32 batch_start = 0;
  u32 count;
  bool first = true;
  *len = 0;

  while (true) {
    size_t skip = *len;
    count = num - skip;

    if (first) {
      err = bpf_map_lookup_batch(map_fd, NULL, &batch_start,
                                 keys + key_size * skip,
                                 vals + value_size * skip, &count, NULL);
      first = false;
    } else {
      err = bpf_map_lookup_batch(map_fd, &batch_start, &batch_start,
                                 keys + key_size * skip,
                                 vals + value_size * skip, &count, NULL);
    }

    if (err && errno != ENOENT) {
      EXPECT0(err);
    }

    *len += count;

    if (err && errno == ENOENT) {
      break;
    }
  }
}

void bpf_get_dump(Dump *dump) {
#define do_dump(map, field)                                                    \
  {                                                                            \
    int map_fd = bpf_map__fd(map);                                             \
    assert(ARRAY_LEN(dump->field##_keys) == ARRAY_LEN(dump->field##_vals));    \
    iterate_map_batch(map_fd, dump->field##_keys,                              \
                      sizeof(dump->field##_keys[0]), dump->field##_vals,       \
                      sizeof(dump->field##_vals[0]),                           \
                      ARRAY_LEN(dump->field##_keys), &dump->field##_len);      \
  }

  do_dump(skel->maps.task_cache, task);
}

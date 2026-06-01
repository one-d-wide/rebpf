#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
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

static struct bpf *skel = NULL;
static struct {
  struct bpf_link *ingress;
  u32 ingress_ifindex;
  struct bpf_link *egress;
  u32 egress_ifindex;
  struct bpf_link *cgroup_egress;
  int reload_config_fd;
  int get_stats_fd;
  struct bpf_link *iter_file;
  int iter_file_fd;
  struct bpf_link *dump_socket_procs_file;
  int dump_socket_procs_fd;
  u64 last_gen;
} links = {0};

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

  int cgroup_fd;
  EXPECT((cgroup_fd = open("/sys/fs/cgroup/", O_RDONLY)) >= 0);
  EXPECT((links.cgroup_egress = bpf_program__attach_cgroup(
              skel->progs.cgroup_skb_egress, cgroup_fd)) != 0);
  EXPECT(bpf_program__attach_cgroup(skel->progs.cgroup_socket_create,
                                    cgroup_fd) != 0);
  EXPECT(bpf_program__attach_cgroup(skel->progs.cgroup_socket_release,
                                    cgroup_fd) != 0);
  EXPECT(links.iter_file =
             bpf_program__attach_iter(skel->progs.refresh_sockets, NULL));
  links.iter_file_fd = bpf_link__fd(links.iter_file);

  EXPECT(links.dump_socket_procs_file =
             bpf_program__attach_iter(skel->progs.dump_socket_procs, NULL));
  links.dump_socket_procs_fd = bpf_link__fd(links.dump_socket_procs_file);

  links.reload_config_fd = bpf_program__fd(skel->progs.reload_config);
  links.get_stats_fd = bpf_program__fd(skel->progs.get_stats);

  EXPECT(setrlimit(RLIMIT_MEMLOCK, &rlim_old) == 0);
  close(cgroup_fd);
}

void bpf_unload() {
  if (links.egress) {
    EXPECT0(bpf_link__destroy(links.egress));
    links.egress = NULL;
  }

  if (links.ingress) {
    EXPECT0(bpf_link__destroy(links.ingress));
    links.ingress = NULL;
  }
}

int bpf_reload_config(BpfConfig *conf) {
  if (conf->from_dev.ifindex != links.ingress_ifindex ||
      conf->to_dev.ifindex != links.egress_ifindex || !links.egress ||
      !links.ingress) {

    bpf_unload();

    EXPECT(conf->from_dev.ifindex != conf->to_dev.ifindex);

    if (!(links.egress = bpf_program__attach_tcx(
              skel->progs.egress, conf->from_dev.ifindex, NULL))) {
      return 1;
    }

    links.ingress = bpf_program__attach_tcx(skel->progs.ingress,
                                            conf->to_dev.ifindex, NULL);

    links.ingress_ifindex = conf->from_dev.ifindex;
    links.egress_ifindex = conf->to_dev.ifindex;
  }

  struct bpf_test_run_opts run_opts = {
      .sz = sizeof(run_opts),
      .ctx_in = conf,
      .ctx_size_in = sizeof(*conf),
  };

  conf->from_dev.is_ingress = true;
  conf->to_dev.is_ingress = false;

  EXPECT(bpf_prog_test_run_opts(links.reload_config_fd, &run_opts) == 0);
  EXPECT0(run_opts.retval);

  if (links.last_gen != conf->generation) {
    links.last_gen = conf->generation;

    int iter_fd;
    EXPECT((iter_fd = bpf_iter_create(links.iter_file_fd)) >= 0);

    int err;
    char buf[64];
    while ((err = read(iter_fd, &buf, sizeof(buf))) == -1 && errno == EAGAIN)
      ;
    EXPECT(err == 0);
    close(iter_fd);
  }

  return 0;
}

void bpf_get_stats(Stats *stats) {
  struct bpf_test_run_opts run_opts = {
      .sz = sizeof(run_opts),
      .ctx_in = stats,
      .ctx_size_in = sizeof(*stats),
  };

  EXPECT0(bpf_prog_test_run_opts(links.get_stats_fd, &run_opts));
  EXPECT0(run_opts.retval);
}

void bpf_get_proc_names(char **ptr, u64 *len, u64 *cap) {
  int iter_fd;
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
  close(iter_fd);
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

  do_dump(skel->maps.socket_cache, socket);
  do_dump(skel->maps.task_cache, task);
  do_dump(skel->maps.nat_cache, nat);
}

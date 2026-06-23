#ifndef BPF_SHARED_H
#define BPF_SHARED_H

#ifdef BINDGEN
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define NULL (void *)0
#endif // BINDGEN

#ifndef BINDGEN

#define ALIGN_UP(x, align_to) (((x) + ((align_to) - 1)) & ~((align_to) - 1))
#define ARRAY_LEN(arr) sizeof((arr)) / sizeof((arr)[0])
#define MIN(l, r) ((l) < (r) ? (l) : (r))

#endif // BINDGEN

#define PAGE_SIZE 4096
#define DFA_MAX_SIZE (1ull << 20) // ~1MB
#define ARENA_SIZE (1ull << 21) // ~2MB

#define DESCEND_MAX 1024
#define MATCHES_BUF_MAX 128  // Match structs
#define STRINGS_BUF_MAX 4096 // bytes

#define DNS_PORT 53

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

enum MatchKind : u8 {
  MATCH_KIND_INVAL,
  MATCH_KIND_BASENAME,
  MATCH_KIND_FULL,
  MATCH_KIND_SUBSTR,
  MATCH_KIND_PREFIX,
  __MATCH_KIND_MAX,
};

const char *MATCH_KIND_STRINGS[] = {
    "invalid", "basename", "full", "prefix", "substring", NULL,
};

enum MatchDir : u8 {
  MATCH_DIR_INVAL,
  MATCH_DIR_REDIRECT,
  MATCH_DIR_BYPASS,
};

const char *MATCH_DIR_STRINGS[] = {
    "invalid",
    "redirect",
    "bypass",
    NULL,
};

typedef struct MatchStr MatchStr;
struct MatchStr {
  enum MatchKind kind;
  enum MatchDir dir;
  u32 uid;
  char *pat;
};

typedef struct DFA DFA;
struct DFA {
  u32 dfa_off;
  u32 start;
  u16 eoi;
  u32 fin_min;
  u32 fin_max;
};

typedef struct BpfConfig BpfConfig;
struct BpfConfig {
  bool enable;
  bool enable_dns;
  bool check_parents;
  u32 mark;

  u32 nmatches;
  u32 strings_len;
  MatchStr *matches;

  void *arena_buf;
  u32 arena_buf_len;
  u32 arena_npages;

  u64 generation; // Incremented each time matches change
};

typedef struct ProcFdEntry ProcFdEntry;
struct ProcFdEntry {
  u64 pid;
  u64 start_boottime;
  u32 fd;
  u32 _pad;
};

#define PATH_MAX 4096

#define TASK_CACHE_MAX 1024
typedef struct TaskId TaskId;
struct TaskId {
  u64 pid;
  u64 time;
};

typedef struct Dump Dump;
struct Dump {
  TaskId task_keys[TASK_CACHE_MAX];
  bool task_vals[TASK_CACHE_MAX];
  u64 task_len;
};

void bpf_drop_caps();
void bpf_init();
int bpf_reload_config(BpfConfig *conf);
void bpf_get_proc_names(char **ptr, u64 *len, u64 *cap);
void bpf_get_dump(Dump *dump);
void bpf_run_dns_ringbuf(int (*callback)(void *ctx, void *data, size_t data_sz),
                  void *ctx);

#endif // BPF_SHARED_H

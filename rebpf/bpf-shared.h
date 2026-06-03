#ifndef BPF_SHARED_H
#define BPF_SHARED_H

#ifdef BINDGEN
#include <stdbool.h>
#include <stdint.h>
#define NULL (void *)0
#endif // BINDGEN

#ifndef BINDGEN

#define ARRAY_LEN(arr) sizeof((arr)) / sizeof((arr)[0])
#define MIN(l, r) ((l) < (r) ? (l) : (r))

#endif // BINDGEN

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

typedef struct Match Match;
struct Match {
  u8 kind;
  u8 dir;
  u32 uid;
  u32 pat_off;
  u32 pat_len; // not counting null
};

typedef struct Redirect Redirect;
struct Redirect {
  bool checked_mac;
  bool is_ingress;
  u8 family;
  u32 ifindex;
  bool set_l2; // whether the device has l2 address
  u8 mac[6];   // l2 address (ethernet)
  u32 addr[4]; // l3 address (internet)
  bool set_nexthop_mac;
  bool set_nexthop_addr;
  u8 nexthop_mac[6];
  u32 nexthop_addr[4];
  char ifname[16];
};

typedef struct Stats Stats;
struct Stats {
  u64 tx_bytes;
  u64 rx_bytes;
  u64 time_ns;
};

typedef struct BpfConfig BpfConfig;
struct BpfConfig {
  bool enable;
  bool drop;
  bool check_parents;
  u32 mark;
  Redirect from_dev;
  Redirect to_dev;
  u32 nmatches;
  u32 strings_len;
  MatchStr *matches;

  bool allow_lan;
  bool spoof_dns;
  u32 spoof_dns_ipv4;

  u64 generation; // Incremented each time matches change
};

#define SOCKET_CACHE_MAX 4096

#define TASK_CACHE_MAX 1024
typedef struct TaskId TaskId;
struct TaskId {
  u64 pid;
  u64 time;
};

#define NAT_CACHE_MAX 1024
typedef struct NatKey NatKey;
struct NatKey {
  u32 remote_ip;
  u32 local_ip;
  u16 remote_port;
  u16 local_port;
};

typedef struct NatVal NatVal;
struct NatVal {
  u32 spoofed_remote_ip;
};

typedef struct Dump Dump;
struct Dump {
  u64 socket_keys[SOCKET_CACHE_MAX];
  bool socket_vals[SOCKET_CACHE_MAX];
  u64 socket_len;

  TaskId task_keys[TASK_CACHE_MAX];
  bool task_vals[TASK_CACHE_MAX];
  u64 task_len;

  NatKey nat_keys[NAT_CACHE_MAX];
  NatVal nat_vals[NAT_CACHE_MAX];
  u64 nat_len;
};

void bpf_drop_caps();
void bpf_init();
void bpf_unload();
int bpf_reload_config(BpfConfig *conf);
void bpf_get_stats(Stats *stats);
void bpf_get_proc_names(char **ptr, u64 *len, u64 *cap);
void bpf_get_dump(Dump *dump);

#endif // BPF_SHARED_H

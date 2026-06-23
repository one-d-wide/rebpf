#ifndef BPF_DNS_C
#define BPF_DNS_C

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf-dfa.c"
#include "bpf-dns.h"
#include "bpf-shared.h"

//
// DNS parsing within eBPF. Unused for now.
//

[[maybe_unused]]
static int match_pat(u8 *buf, u32 buf_len) {
  // There should be code to run a forward DFA matching DNS names like "\x07example\x03com\x00"
  return 0;
}

// Note:
//
// Parsing dns directly from the skb is too complicated. The variable size of
// the each query appears to force the verifier to fork too much in loops.
//
// The dns packet could be copied in a temporary buffer to make the verifier
// less cautious.
[[maybe_unused]]
static int parse_dns_from_buf(u8 *buf, u32 buf_len) {
  if (buf_len > 512) {
    return 0;
  }

  struct dnshdr *dns = (struct dnshdr *)buf;

  u16 acount = bpf_ntohs(dns->ancount);
  u16 qcount = bpf_ntohs(dns->qdcount);

  int pos = sizeof(*dns);

  u32 rr;
  bpf_for(rr, 1, acount + qcount + 1) {
    if (pos >= buf_len) {
      return 0;
    }

    bpf_printk("parsing query %u at offset=%i", rr, pos);

    u8 label_len = buf[pos];
    pos += 1;

    bpf_printk("label_len=%i", label_len);

    u8 *name_ptr = NULL;
    u32 name_off = 0;

    if (label_len < 192) {
      // Label is in-line

      name_off = pos;
      name_ptr = &buf[pos];
      bpf_printk("inline label");

      int len = bpf_strnlen((char*)name_ptr, buf_len - pos);

      // while (pos < buf_len && buf[pos]) {
      //   pos += buf[pos];
      // }
      //
      // if (pos >= buf_len) {
      //   return 1;
      // }

      if (len < 0 || len > 256) {
        return 0;
      }

      pos += len + 1;
    } else {
      // Label is compressed (a reference to another location)

      name_off = ((u32)(label_len - 192) << 8) | buf[pos];
      name_ptr = (u8 *)dns + name_off;

      bpf_printk("compressed label, offset=%i", name_off);

      pos += 1;
    }

    if (pos >= buf_len) {
      return 0;
    }

    bpf_printk("%i first_label=%s", rr, name_ptr);

    if (rr <= qcount) {
      bpf_printk("QUERY %i/%i: %s", rr, qcount, name_ptr);

      pos += 2; // type
      pos += 2; // class
      continue;
    }

    bpf_printk("ANSWER %i/%i: %s", rr - qcount, acount, name_ptr);

    // if ((void *)(p + 10) > data_end)
    //   return -1;

    u16 type = bpf_htons(*(__be16 *)(buf + pos));
    pos += 2; // type

    u16 class = bpf_htons(*(__be16 *)(buf + pos));
    pos += 2; // class

    u32 ttl = bpf_htonl(*(__be32 *)(buf + pos));
    pos += 4; // ttl

    u16 data_len = bpf_htons(*(__be16 *)(buf + pos));
    pos += 2; // data_len

    bpf_printk("type=%i, class=%i, ttl=%is, data_len=%i", type, class, ttl,
               data_len);

    u32 data_off = pos;
    pos += data_len; // data

    if (pos > buf_len) {
      break;
    }

    switch (type) {
    case DNS_QTYPE_A:
      if (data_len < 4) {
        return 0;
      }

      __be32 ipv4 = *(__be32 *)(buf + data_off);
      print_ipv4("QTYPE_A:", ipv4);
    }
  }

  return 0;
}

#endif
